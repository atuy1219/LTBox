//! TB376FC -> TB390FU cross-flash analysis and offline image preparation.
//!
//! This module never flashes a device. It validates one fixed profile and
//! prepares two images for an officially bootloader-unlocked TB376FC:
//!
//! - `vendor_boot.img`: only the root FDT `region,country` properties for the
//!   supported Tuna boards are changed from ROW to PRC.
//! - `vbmeta.img`: AVB verification and hashtree-disable flags are enabled in
//!   the same header field used by fastboot's disable-verification operation.
//!
//! Both edits invalidate Lenovo's original signatures. Never use the outputs
//! on a locked bootloader and never relock after installing them.

use fs_err as fs;
use ltbox_core::{LtboxError, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::Path;

use crate::avb;
use crate::region::RegionTarget;

pub const SOURCE_MODEL: &str = "TB376FC";
pub const TARGET_MODEL: &str = "TB390FU";
pub const DEVICE_PRODUCT: &str = "malbec";
pub const DEVICE_HWBOARD_ID: &str = "SM8735P_8+128_22";
pub const EXPECTED_FIXED_KEY_SHA1: &str = "8fcb864f11f53ed11284615fb67685522085d3a2";
pub const PROFILE_NAME: &str = "tb376fc-to-tb390fu-row-on-prc";

pub const PROTECTED_PARTITIONS: &[&str] = &[
    "proinfo",
    "persist",
    "modemst1",
    "modemst2",
    "fsg",
    "fsc",
    "frp",
    "lenovolock",
    "devinfo",
    "keystore",
];

const REQUIRED_IMAGES: &[&str] = &[
    "vendor_boot.img",
    "vbmeta.img",
    "vbmeta_system.img",
    "boot.img",
];
const OPTIONAL_IMAGES: &[&str] = &["init_boot.img", "dtbo.img", "recovery.img"];

const AVB_HEADER_SIZE: usize = 256;
const AVB_FLAGS_OFFSET: usize = 120;
const AVB_MAGIC: &[u8; 4] = b"AVB0";
const AVB_HASHTREE_DISABLED: u32 = 1;
const AVB_VERIFICATION_DISABLED: u32 = 2;

const FDT_MAGIC: u32 = 0xD00D_FEED;
const FDT_MAGIC_BYTES: [u8; 4] = [0xD0, 0x0D, 0xFE, 0xED];
const FDT_HEADER_SIZE: usize = 40;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const EXPECTED_SUPPORTED_FDTS: usize = 3;

#[derive(Debug, Clone, Serialize)]
pub struct ImageAnalysis {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub algorithm: String,
    pub rollback_index: u64,
    pub rollback_index_location: u32,
    pub flags: u32,
    pub partition_name: Option<String>,
    pub public_key_sha1: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FirmwareAnalysis {
    pub profile: String,
    pub firmware_dir: String,
    pub source_model: String,
    pub target_model: String,
    pub required_device_product: String,
    pub required_hwboard_id: String,
    pub required_bootloader_unlocked: bool,
    pub detected_region: String,
    pub firmware_fingerprint: String,
    pub expected_fixed_key_sha1: String,
    pub protected_partitions: Vec<String>,
    pub images: Vec<ImageAnalysis>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreparedImage {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub transformation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreparationManifest {
    pub profile: String,
    pub input_dir: String,
    pub output_dir: String,
    pub analysis: FirmwareAnalysis,
    pub outputs: Vec<PreparedImage>,
    pub vbmeta_old_flags: u32,
    pub vbmeta_new_flags: u32,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VbmetaFlagPatch {
    pub old_flags: u32,
    pub new_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedBoard {
    Tuna,
    Tunap,
}

#[derive(Debug, Clone, Copy)]
struct SupportedFdt {
    board: SupportedBoard,
    region: RegionTarget,
    region_value_start: usize,
}

#[derive(Debug, Clone, Copy)]
struct FdtBounds {
    base: usize,
    total_end: usize,
    struct_start: usize,
    struct_end: usize,
    strings_start: usize,
    strings_end: usize,
}

pub fn analyze_tb390_firmware(firmware_dir: &Path) -> Result<FirmwareAnalysis> {
    if !firmware_dir.is_dir() {
        return Err(LtboxError::FileNotFound(firmware_dir.display().to_string()));
    }
    for name in REQUIRED_IMAGES {
        require_file(&firmware_dir.join(name))?;
    }

    let vendor_boot = firmware_dir.join("vendor_boot.img");
    let vendor_boot_data = fs::read(&vendor_boot)?;
    let (detected_region, _) = validate_supported_fdt_set(&vendor_boot_data)?;
    if detected_region != RegionTarget::Row {
        return Err(LtboxError::Patch(format!(
            "TB390FU source firmware must have ROW root region,country values, detected {detected_region:?}"
        )));
    }

    let mut images = Vec::new();
    for name in REQUIRED_IMAGES.iter().chain(OPTIONAL_IMAGES.iter()) {
        let path = firmware_dir.join(name);
        if path.is_file() {
            images.push(analyze_image(&path, name)?);
        }
    }

    let firmware_fingerprint = images
        .iter()
        .find(|image| image.name.eq_ignore_ascii_case("vbmeta_system.img"))
        .and_then(|image| image.fingerprint.clone())
        .ok_or_else(|| LtboxError::Avb("vbmeta_system.img has no build fingerprint".to_string()))?;
    if !firmware_fingerprint.contains(TARGET_MODEL) {
        return Err(LtboxError::Patch(format!(
            "firmware fingerprint is not for {TARGET_MODEL}: {firmware_fingerprint}"
        )));
    }

    for image in &images {
        if let Some(key) = image.public_key_sha1.as_deref()
            && !key.eq_ignore_ascii_case(EXPECTED_FIXED_KEY_SHA1)
        {
            return Err(LtboxError::Avb(format!(
                "{} uses unexpected AVB key {} (expected {})",
                image.name, key, EXPECTED_FIXED_KEY_SHA1
            )));
        }
    }

    let mut warnings = vec![
        "Offline analysis cannot read device rollback floors; compare boot and vbmeta_system indices before flashing.".to_string(),
        "Only use this profile on an officially unlocked TB376FC reporting product=malbec and hwboardid=SM8735P_8+128_22.".to_string(),
        "Keep hardware country and device-specific partitions unchanged.".to_string(),
    ];
    for name in OPTIONAL_IMAGES {
        if !firmware_dir.join(name).is_file() {
            warnings.push(format!("optional image not present: {name}"));
        }
    }

    Ok(FirmwareAnalysis {
        profile: PROFILE_NAME.to_string(),
        firmware_dir: firmware_dir.display().to_string(),
        source_model: SOURCE_MODEL.to_string(),
        target_model: TARGET_MODEL.to_string(),
        required_device_product: DEVICE_PRODUCT.to_string(),
        required_hwboard_id: DEVICE_HWBOARD_ID.to_string(),
        required_bootloader_unlocked: true,
        detected_region: "ROW".to_string(),
        firmware_fingerprint,
        expected_fixed_key_sha1: EXPECTED_FIXED_KEY_SHA1.to_string(),
        protected_partitions: PROTECTED_PARTITIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        images,
        warnings,
    })
}

pub fn prepare_tb376_crossflash_images(
    firmware_dir: &Path,
    output_dir: &Path,
) -> Result<PreparationManifest> {
    let analysis = analyze_tb390_firmware(firmware_dir)?;
    if same_path(firmware_dir, output_dir) {
        return Err(LtboxError::Patch(
            "output directory must differ from the firmware directory".to_string(),
        ));
    }
    fs::create_dir_all(output_dir)?;

    let vendor_boot_out = output_dir.join("vendor_boot.img");
    let replacements = patch_vendor_boot_region_country(
        &firmware_dir.join("vendor_boot.img"),
        &vendor_boot_out,
        RegionTarget::Prc,
    )?;

    let vbmeta_out = output_dir.join("vbmeta.img");
    let vbmeta_patch = patch_top_level_vbmeta_flags(
        &firmware_dir.join("vbmeta.img"),
        &vbmeta_out,
        AVB_HASHTREE_DISABLED | AVB_VERIFICATION_DISABLED,
    )?;

    let outputs = vec![
        prepared_image(
            "vendor_boot.img",
            &vendor_boot_out,
            format!(
                "patched {replacements} supported root region,country value(s) ROW -> PRC; the retained Lenovo AVB footer is stale after the payload edit"
            ),
        )?,
        prepared_image(
            "vbmeta.img",
            &vbmeta_out,
            format!(
                "set top-level AVB flags {} -> {}; this intentionally invalidates the original Lenovo signature",
                vbmeta_patch.old_flags, vbmeta_patch.new_flags
            ),
        )?,
    ];

    let manifest = PreparationManifest {
        profile: PROFILE_NAME.to_string(),
        input_dir: firmware_dir.display().to_string(),
        output_dir: output_dir.display().to_string(),
        analysis,
        outputs,
        vbmeta_old_flags: vbmeta_patch.old_flags,
        vbmeta_new_flags: vbmeta_patch.new_flags,
        warnings: vec![
            "PREPARATION ONLY: no device was flashed.".to_string(),
            "Both images require an unlocked bootloader; never relock after installing them.".to_string(),
            "Flash support remains disabled until rollback floors and the full partition compatibility plan are verified on-device.".to_string(),
        ],
    };

    fs::write(
        output_dir.join("tb376fc-crossflash-manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    fs::write(
        output_dir.join("DO_NOT_RELOCK.txt"),
        "For an officially bootloader-unlocked TB376FC only.\nNever relock after installing modified or TB390FU images.\n",
    )?;
    Ok(manifest)
}

/// Patch only the root `region,country` property in the three supported Tuna
/// FDTs embedded in the fixed-profile TB390FU vendor_boot image. Unrelated ROW
/// strings, including the AVB fingerprint, are left untouched.
pub fn patch_vendor_boot_region_country(
    input: &Path,
    output: &Path,
    target: RegionTarget,
) -> Result<usize> {
    require_file(input)?;
    let original = fs::read(input)?;
    let (source, fdts) = validate_supported_fdt_set(&original)?;
    if source == target {
        return Err(LtboxError::Patch(format!(
            "{} already reports region {target:?}",
            input.display()
        )));
    }

    let source_value = region_value(source);
    let target_value = region_value(target);
    let mut patched = original.clone();
    for fdt in &fdts {
        let value_end = fdt
            .region_value_start
            .checked_add(source_value.len())
            .ok_or_else(|| LtboxError::Patch("region,country offset overflow".to_string()))?;
        if patched.get(fdt.region_value_start..value_end) != Some(&source_value[..]) {
            return Err(LtboxError::Patch(format!(
                "supported FDT region,country changed before patch at offset 0x{:X}",
                fdt.region_value_start
            )));
        }
        patched[fdt.region_value_start..value_end].copy_from_slice(&target_value);
    }

    let changed_bytes = original
        .iter()
        .zip(&patched)
        .filter(|(before, after)| before != after)
        .count();
    if fdts.len() != EXPECTED_SUPPORTED_FDTS || changed_bytes != EXPECTED_SUPPORTED_FDTS * 3 {
        return Err(LtboxError::Patch(format!(
            "unsafe vendor_boot region patch: {} replacements changed {changed_bytes} bytes",
            fdts.len()
        )));
    }

    let (verified_region, verified_fdts) = validate_supported_fdt_set(&patched)?;
    if verified_region != target || verified_fdts.len() != EXPECTED_SUPPORTED_FDTS {
        return Err(LtboxError::Patch(
            "patched vendor_boot failed region,country verification".to_string(),
        ));
    }

    fs::write(output, patched)?;
    ensure_same_size(input, output, "vendor_boot region patch")?;
    Ok(fdts.len())
}

pub fn patch_top_level_vbmeta_flags(
    input: &Path,
    output: &Path,
    flags_to_enable: u32,
) -> Result<VbmetaFlagPatch> {
    require_file(input)?;
    let mut data = fs::read(input)?;
    if data.len() < AVB_HEADER_SIZE || &data[..4] != AVB_MAGIC {
        return Err(LtboxError::Avb(format!(
            "{} is not a top-level AVB vbmeta image",
            input.display()
        )));
    }

    let old_flags = be32(&data[AVB_FLAGS_OFFSET..AVB_FLAGS_OFFSET + 4]);
    let new_flags = old_flags | flags_to_enable;
    data[AVB_FLAGS_OFFSET..AVB_FLAGS_OFFSET + 4].copy_from_slice(&new_flags.to_be_bytes());
    fs::write(output, data)?;
    ensure_same_size(input, output, "vbmeta flag patch")?;
    Ok(VbmetaFlagPatch {
        old_flags,
        new_flags,
    })
}

fn validate_supported_fdt_set(data: &[u8]) -> Result<(RegionTarget, Vec<SupportedFdt>)> {
    let mut supported = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = find_subslice(&data[cursor..], &FDT_MAGIC_BYTES) {
        let base = cursor + relative;
        let Some(bounds) = parse_fdt_bounds(data, base) else {
            cursor = base.saturating_add(FDT_MAGIC_BYTES.len());
            continue;
        };
        if let Some(fdt) = parse_supported_fdt(data, bounds)? {
            supported.push(fdt);
        }
        cursor = bounds.total_end;
    }

    if supported.len() != EXPECTED_SUPPORTED_FDTS {
        return Err(LtboxError::Patch(format!(
            "expected exactly {EXPECTED_SUPPORTED_FDTS} supported Tuna FDT region,country properties, found {}",
            supported.len()
        )));
    }
    let tuna_count = supported
        .iter()
        .filter(|fdt| fdt.board == SupportedBoard::Tuna)
        .count();
    let tunap_count = supported
        .iter()
        .filter(|fdt| fdt.board == SupportedBoard::Tunap)
        .count();
    if tuna_count != 2 || tunap_count != 1 {
        return Err(LtboxError::Patch(format!(
            "unexpected supported FDT board set: qcom,tuna={tuna_count}, qcom,tunap={tunap_count}"
        )));
    }
    let region = supported[0].region;
    if supported.iter().any(|fdt| fdt.region != region) {
        return Err(LtboxError::Patch(
            "supported FDT region,country values are mixed".to_string(),
        ));
    }
    Ok((region, supported))
}

fn parse_fdt_bounds(data: &[u8], base: usize) -> Option<FdtBounds> {
    let header_end = base.checked_add(FDT_HEADER_SIZE)?;
    if header_end > data.len() || be32(data.get(base..base + 4)?) != FDT_MAGIC {
        return None;
    }
    let total_size = usize::try_from(be32(data.get(base + 4..base + 8)?)).ok()?;
    let struct_offset = usize::try_from(be32(data.get(base + 8..base + 12)?)).ok()?;
    let strings_offset = usize::try_from(be32(data.get(base + 12..base + 16)?)).ok()?;
    let strings_size = usize::try_from(be32(data.get(base + 32..base + 36)?)).ok()?;
    let struct_size = usize::try_from(be32(data.get(base + 36..base + 40)?)).ok()?;
    if total_size < FDT_HEADER_SIZE {
        return None;
    }
    let total_end = base.checked_add(total_size)?;
    let struct_start = base.checked_add(struct_offset)?;
    let struct_end = struct_start.checked_add(struct_size)?;
    let strings_start = base.checked_add(strings_offset)?;
    let strings_end = strings_start.checked_add(strings_size)?;
    if total_end > data.len()
        || struct_start < header_end
        || struct_end > total_end
        || strings_start < header_end
        || strings_end > total_end
    {
        return None;
    }
    Some(FdtBounds {
        base,
        total_end,
        struct_start,
        struct_end,
        strings_start,
        strings_end,
    })
}

fn parse_supported_fdt(data: &[u8], bounds: FdtBounds) -> Result<Option<SupportedFdt>> {
    let mut pos = bounds.struct_start;
    let mut depth = 0usize;
    let mut root_compatible = None;
    let mut root_region = None;
    let mut saw_root_compatible = false;
    let mut saw_root_region = false;
    let mut saw_end = false;
    while pos + 4 <= bounds.struct_end {
        let token = be32(&data[pos..pos + 4]);
        pos += 4;
        match token {
            FDT_BEGIN_NODE => {
                let name_end = find_nul(data, pos, bounds.struct_end).ok_or_else(|| {
                    LtboxError::Patch(format!(
                        "unterminated FDT node name at vendor_boot offset 0x{:X}",
                        pos
                    ))
                })?;
                pos = align4_checked(name_end + 1)
                    .ok_or_else(|| LtboxError::Patch("FDT node alignment overflow".to_string()))?;
                if pos > bounds.struct_end {
                    return Err(LtboxError::Patch(
                        "FDT node name exceeds structure block".to_string(),
                    ));
                }
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| LtboxError::Patch("FDT node depth overflow".to_string()))?;
            }
            FDT_END_NODE => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| LtboxError::Patch("unexpected FDT_END_NODE".to_string()))?;
            }
            FDT_PROP => {
                if pos + 8 > bounds.struct_end {
                    return Err(LtboxError::Patch(
                        "truncated FDT property header".to_string(),
                    ));
                }
                let value_len = usize::try_from(be32(&data[pos..pos + 4])).map_err(|_| {
                    LtboxError::Patch("FDT property length conversion failed".to_string())
                })?;
                let name_offset = usize::try_from(be32(&data[pos + 4..pos + 8])).map_err(|_| {
                    LtboxError::Patch("FDT property name offset conversion failed".to_string())
                })?;
                pos += 8;
                let value_start = pos;
                let value_end = value_start
                    .checked_add(value_len)
                    .ok_or_else(|| LtboxError::Patch("FDT property length overflow".to_string()))?;
                if value_end > bounds.struct_end {
                    return Err(LtboxError::Patch(
                        "FDT property exceeds structure block".to_string(),
                    ));
                }
                if depth == 1 {
                    let name_start =
                        bounds
                            .strings_start
                            .checked_add(name_offset)
                            .ok_or_else(|| {
                                LtboxError::Patch("FDT property name offset overflow".to_string())
                            })?;
                    if name_start >= bounds.strings_end {
                        return Err(LtboxError::Patch(
                            "FDT property name is outside strings block".to_string(),
                        ));
                    }
                    let name_end =
                        find_nul(data, name_start, bounds.strings_end).ok_or_else(|| {
                            LtboxError::Patch("unterminated FDT property name".to_string())
                        })?;
                    let name = &data[name_start..name_end];
                    let value = &data[value_start..value_end];
                    if name == b"compatible" {
                        if saw_root_compatible {
                            return Err(LtboxError::Patch(
                                "duplicate root compatible property in FDT".to_string(),
                            ));
                        }
                        saw_root_compatible = true;
                        root_compatible = supported_board(value)?;
                    } else if name == b"region,country" {
                        if saw_root_region {
                            return Err(LtboxError::Patch(
                                "duplicate root region,country property in FDT".to_string(),
                            ));
                        }
                        saw_root_region = true;
                        let region = match value {
                            b"ROW\0" => RegionTarget::Row,
                            b"PRC\0" => RegionTarget::Prc,
                            _ => {
                                return Err(LtboxError::Patch(format!(
                                    "unsupported root region,country value in FDT at vendor_boot offset 0x{:X}",
                                    bounds.base
                                )));
                            }
                        };
                        root_region = Some((region, value_start));
                    }
                }
                pos = align4_checked(value_end).ok_or_else(|| {
                    LtboxError::Patch("FDT property alignment overflow".to_string())
                })?;
                if pos > bounds.struct_end {
                    return Err(LtboxError::Patch(
                        "FDT property padding exceeds structure block".to_string(),
                    ));
                }
            }
            FDT_NOP => {}
            FDT_END => {
                saw_end = true;
                break;
            }
            other => {
                return Err(LtboxError::Patch(format!(
                    "unsupported FDT token 0x{other:08X} at vendor_boot offset 0x{:X}",
                    pos - 4
                )));
            }
        }
    }
    if !saw_end || depth != 0 {
        return Err(LtboxError::Patch(format!(
            "invalid FDT structure at vendor_boot offset 0x{:X}",
            bounds.base
        )));
    }
    match (root_compatible, root_region) {
        (Some(board), Some((region, region_value_start))) => Ok(Some(SupportedFdt {
            board,
            region,
            region_value_start,
        })),
        _ => Ok(None),
    }
}

fn supported_board(value: &[u8]) -> Result<Option<SupportedBoard>> {
    let mut tuna = false;
    let mut tunap = false;
    for item in value
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
    {
        match item {
            b"qcom,tuna" => tuna = true,
            b"qcom,tunap" => tunap = true,
            _ => {}
        }
    }
    match (tuna, tunap) {
        (true, false) => Ok(Some(SupportedBoard::Tuna)),
        (false, true) => Ok(Some(SupportedBoard::Tunap)),
        (false, false) => Ok(None),
        (true, true) => Err(LtboxError::Patch(
            "FDT compatible contains both qcom,tuna and qcom,tunap".to_string(),
        )),
    }
}

fn analyze_image(path: &Path, name: &str) -> Result<ImageAnalysis> {
    let info = avb::extract_image_avb_info(path)?;
    let fingerprint = avb::build_fingerprint(&info);
    Ok(ImageAnalysis {
        name: name.to_string(),
        size: fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
        algorithm: info.algorithm,
        rollback_index: info.rollback_index,
        rollback_index_location: info.rollback_index_location,
        flags: info.flags,
        partition_name: info.partition_name,
        public_key_sha1: info.public_key_sha1,
        fingerprint,
    })
}

fn prepared_image(name: &str, path: &Path, transformation: String) -> Result<PreparedImage> {
    Ok(PreparedImage {
        name: name.to_string(),
        path: path.display().to_string(),
        size: fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
        transformation,
    })
}

fn require_file(path: &Path) -> Result<()> {
    if !path.is_file() {
        return Err(LtboxError::FileNotFound(path.display().to_string()));
    }
    Ok(())
}

fn ensure_same_size(input: &Path, output: &Path, operation: &str) -> Result<()> {
    if fs::metadata(input)?.len() != fs::metadata(output)?.len() {
        return Err(LtboxError::Patch(format!(
            "image size changed during {operation}"
        )));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let digest = Sha256::digest(fs::read(path)?);
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02X}");
    }
    Ok(output)
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn region_value(region: RegionTarget) -> [u8; 4] {
    match region {
        RegionTarget::Prc => *b"PRC\0",
        RegionTarget::Row => *b"ROW\0",
    }
}

fn align4_checked(value: usize) -> Option<usize> {
    value.checked_add(3).map(|aligned| aligned & !3)
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn find_nul(data: &[u8], start: usize, end: usize) -> Option<usize> {
    data.get(start..end)?
        .iter()
        .position(|byte| *byte == 0)
        .map(|relative| start + relative)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_vbmeta_flags_without_changing_size() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("vbmeta.img");
        let output = tmp.path().join("vbmeta-patched.img");
        let mut data = vec![0u8; 4096];
        data[..4].copy_from_slice(AVB_MAGIC);
        data[AVB_FLAGS_OFFSET..AVB_FLAGS_OFFSET + 4].copy_from_slice(&4u32.to_be_bytes());
        fs::write(&input, &data).unwrap();

        let result = patch_top_level_vbmeta_flags(&input, &output, 3).unwrap();
        assert_eq!(result.old_flags, 4);
        assert_eq!(result.new_flags, 7);
        let patched = fs::read(output).unwrap();
        assert_eq!(patched.len(), data.len());
        assert_eq!(be32(&patched[AVB_FLAGS_OFFSET..AVB_FLAGS_OFFSET + 4]), 7);
    }

    #[test]
    fn rejects_non_vbmeta_input() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("not-vbmeta.img");
        let output = tmp.path().join("out.img");
        fs::write(&input, vec![0u8; AVB_HEADER_SIZE]).unwrap();
        assert!(patch_top_level_vbmeta_flags(&input, &output, 3).is_err());
    }

    #[test]
    fn detects_fixed_row_fdt_set_with_unrelated_fdt() {
        let data = build_vendor_boot(&[
            ("qcom,other", None),
            ("qcom,tuna", Some(RegionTarget::Row)),
            ("qcom,tuna", Some(RegionTarget::Row)),
            ("qcom,tunap", Some(RegionTarget::Row)),
        ]);
        let (region, fdts) = validate_supported_fdt_set(&data).unwrap();
        assert_eq!(region, RegionTarget::Row);
        assert_eq!(fdts.len(), 3);
    }

    #[test]
    fn region_country_patch_changes_exactly_nine_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("vendor_boot.img");
        let output = tmp.path().join("vendor_boot-patched.img");
        let data = build_vendor_boot(&[
            ("qcom,other", None),
            ("qcom,tuna", Some(RegionTarget::Row)),
            ("qcom,tuna", Some(RegionTarget::Row)),
            ("qcom,tunap", Some(RegionTarget::Row)),
        ]);
        fs::write(&input, &data).unwrap();
        let count = patch_vendor_boot_region_country(&input, &output, RegionTarget::Prc).unwrap();
        assert_eq!(count, 3);
        let patched = fs::read(output).unwrap();
        assert_eq!(patched.len(), data.len());
        assert_eq!(
            data.iter()
                .zip(&patched)
                .filter(|(before, after)| before != after)
                .count(),
            9
        );
        assert!(
            patched
                .windows(b"fingerprint_ROW".len())
                .any(|window| window == b"fingerprint_ROW")
        );
        let (region, fdts) = validate_supported_fdt_set(&patched).unwrap();
        assert_eq!(region, RegionTarget::Prc);
        assert_eq!(fdts.len(), 3);
    }

    #[test]
    fn rejects_mixed_supported_regions() {
        let data = build_vendor_boot(&[
            ("qcom,tuna", Some(RegionTarget::Row)),
            ("qcom,tuna", Some(RegionTarget::Prc)),
            ("qcom,tunap", Some(RegionTarget::Row)),
        ]);
        assert!(validate_supported_fdt_set(&data).is_err());
    }

    #[test]
    fn rejects_incorrect_supported_fdt_count() {
        let data = build_vendor_boot(&[
            ("qcom,tuna", Some(RegionTarget::Row)),
            ("qcom,tunap", Some(RegionTarget::Row)),
        ]);
        assert!(validate_supported_fdt_set(&data).is_err());
    }

    #[test]
    fn rejects_incorrect_supported_board_distribution() {
        let data = build_vendor_boot(&[
            ("qcom,tuna", Some(RegionTarget::Row)),
            ("qcom,tunap", Some(RegionTarget::Row)),
            ("qcom,tunap", Some(RegionTarget::Row)),
        ]);
        assert!(validate_supported_fdt_set(&data).is_err());
    }

    fn build_vendor_boot(specs: &[(&str, Option<RegionTarget>)]) -> Vec<u8> {
        let mut data = b"prefix fingerprint_ROW\0 unrelated ROW\0".to_vec();
        for (compatible, region) in specs {
            data.extend_from_slice(&build_fdt(compatible, *region));
        }
        data.extend_from_slice(b"suffix_ROW\0");
        data
    }

    fn build_fdt(compatible: &str, region: Option<RegionTarget>) -> Vec<u8> {
        let strings = b"compatible\0region,country\0";
        let region_name_offset = u32::try_from(b"compatible\0".len()).unwrap();
        let mut structure = Vec::new();
        push_u32(&mut structure, FDT_BEGIN_NODE);
        structure.extend_from_slice(b"\0");
        pad4(&mut structure);
        push_property(&mut structure, 0, format!("{compatible}\0").as_bytes());
        if let Some(region) = region {
            push_property(&mut structure, region_name_offset, &region_value(region));
        }
        push_u32(&mut structure, FDT_END_NODE);
        push_u32(&mut structure, FDT_END);

        let struct_offset = FDT_HEADER_SIZE + 16;
        let strings_offset = struct_offset + structure.len();
        let total_size = strings_offset + strings.len();
        let mut fdt = Vec::with_capacity(total_size);
        for value in [
            FDT_MAGIC,
            u32::try_from(total_size).unwrap(),
            u32::try_from(struct_offset).unwrap(),
            u32::try_from(strings_offset).unwrap(),
            u32::try_from(FDT_HEADER_SIZE).unwrap(),
            17,
            16,
            0,
            u32::try_from(strings.len()).unwrap(),
            u32::try_from(structure.len()).unwrap(),
        ] {
            push_u32(&mut fdt, value);
        }
        fdt.resize(struct_offset, 0);
        fdt.extend_from_slice(&structure);
        fdt.extend_from_slice(strings);
        fdt
    }

    fn push_property(structure: &mut Vec<u8>, name_offset: u32, value: &[u8]) {
        push_u32(structure, FDT_PROP);
        push_u32(structure, u32::try_from(value.len()).unwrap());
        push_u32(structure, name_offset);
        structure.extend_from_slice(value);
        pad4(structure);
    }

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_be_bytes());
    }

    fn pad4(output: &mut Vec<u8>) {
        while !output.len().is_multiple_of(4) {
            output.push(0);
        }
    }
}
