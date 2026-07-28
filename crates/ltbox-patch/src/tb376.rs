//! TB376FC -> TB390FU cross-flash analysis and offline image preparation.
//!
//! This module never flashes a device. It validates one fixed profile and
//! prepares two images for an officially bootloader-unlocked TB376FC:
//!
//! - `vendor_boot.img`: only the FDT `product_region` property is changed
//!   from ROW to PRC.
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
use crate::region::{self, RegionTarget};

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

pub fn analyze_tb390_firmware(firmware_dir: &Path) -> Result<FirmwareAnalysis> {
    if !firmware_dir.is_dir() {
        return Err(LtboxError::FileNotFound(firmware_dir.display().to_string()));
    }
    for name in REQUIRED_IMAGES {
        require_file(&firmware_dir.join(name))?;
    }

    let vendor_boot = firmware_dir.join("vendor_boot.img");
    let detected_region = region::detect_product_region(&vendor_boot).ok_or_else(|| {
        LtboxError::Patch(format!(
            "{} has no readable product_region node",
            vendor_boot.display()
        ))
    })?;
    if detected_region != RegionTarget::Row {
        return Err(LtboxError::Patch(format!(
            "TB390FU source firmware must be ROW, detected {detected_region:?}"
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
    let replacements = patch_vendor_boot_product_region(
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
                "patched {replacements} product_region value(s) ROW -> PRC; the retained Lenovo AVB footer is stale after the payload edit"
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

/// Patch only `PRC`/`ROW` property values directly under the FDT
/// `product_region` node. Unrelated strings elsewhere in vendor_boot are left
/// untouched.
pub fn patch_vendor_boot_product_region(
    input: &Path,
    output: &Path,
    target: RegionTarget,
) -> Result<usize> {
    require_file(input)?;
    let source = region::detect_product_region(input).ok_or_else(|| {
        LtboxError::Patch(format!("no product_region node in {}", input.display()))
    })?;
    if source == target {
        return Err(LtboxError::Patch(format!(
            "{} already reports region {target:?}",
            input.display()
        )));
    }

    let mut data = fs::read(input)?;
    let node_name = b"product_region\0";
    let source_bytes = region_bytes(source);
    let target_bytes = region_bytes(target);
    let mut cursor = 0usize;
    let mut replacements = 0usize;

    while let Some(relative) = find_subslice(&data[cursor..], node_name) {
        let node_start = cursor + relative;
        let mut pos = align4(node_start + node_name.len());
        for _ in 0..32 {
            if pos + 12 > data.len() || be32(&data[pos..pos + 4]) != 3 {
                break;
            }
            let value_len = be32(&data[pos + 4..pos + 8]) as usize;
            let value_start = pos + 12;
            let value_end = value_start.checked_add(value_len).ok_or_else(|| {
                LtboxError::Patch("product_region property length overflow".to_string())
            })?;
            if value_end > data.len() {
                return Err(LtboxError::Patch(
                    "truncated product_region property".to_string(),
                ));
            }

            let nul = data[value_start..value_end]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(value_len);
            if nul == 3 && &data[value_start..value_start + 3] == source_bytes {
                data[value_start..value_start + 3].copy_from_slice(target_bytes);
                replacements += 1;
            }
            pos = align4(value_end);
        }
        cursor = node_start + node_name.len();
    }

    if replacements == 0 {
        return Err(LtboxError::Patch(format!(
            "no {source:?} product_region property was patched in {}",
            input.display()
        )));
    }
    fs::write(output, data)?;
    ensure_same_size(input, output, "vendor_boot region patch")?;
    Ok(replacements)
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

fn region_bytes(region: RegionTarget) -> &'static [u8; 3] {
    match region {
        RegionTarget::Prc => b"PRC",
        RegionTarget::Row => b"ROW",
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
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
    fn product_region_patch_is_limited_to_node_properties() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("vendor_boot.img");
        let output = tmp.path().join("vendor_boot-patched.img");
        let mut data = b"unrelated.ROW\0product_region\0".to_vec();
        while !data.len().is_multiple_of(4) {
            data.push(0);
        }
        data.extend_from_slice(&3u32.to_be_bytes());
        data.extend_from_slice(&4u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(b"ROW\0");
        data.extend_from_slice(&2u32.to_be_bytes());
        fs::write(&input, &data).unwrap();

        let count = patch_vendor_boot_product_region(&input, &output, RegionTarget::Prc).unwrap();
        assert_eq!(count, 1);
        let patched = fs::read(output).unwrap();
        assert!(patched.windows(14).any(|w| w == b"unrelated.ROW\0"));
        assert!(patched.windows(4).any(|w| w == b"PRC\0"));
    }
}
