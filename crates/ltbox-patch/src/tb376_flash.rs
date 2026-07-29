//! Safe flash-plan construction for the fixed TB376FC -> TB390FU profile.
//!
//! This module is intentionally device-agnostic: it parses the target firmware's
//! rawprogram XML and emits an allow-listed plan. The actual EDL transport lives
//! in the `tb376-globalizer` CLI example under `ltbox-gui`.

use fs_err as fs;
use ltbox_core::xml_catalog::XmlCatalog;
use ltbox_core::{LtboxError, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::tb376::{self, PROTECTED_PARTITIONS};

pub const EXPECTED_TARGET_BUILD: &str = "18.0.10.335";
pub const EXPECTED_PROGRAMMER_SHA256: &str =
    "9C487295ADDBF008024E4D46EEFDFD6F79665BF95F332435361D2102FFDCA162";
pub const FLASH_CONFIRMATION: &str = "TB376FC-TO-TB390FU-I-HAVE-FULL-BACKUP";
pub const SECTOR_SIZE: u64 = 4096;

/// Only Android OS partitions required for the cross-model boot are writable.
/// Qualcomm firmware, bootloader, calibration, country and device-owned state
/// remain on the TB376FC CN build.
pub const FLASH_ALLOWLIST: &[&str] = &[
    "super",
    "boot",
    "init_boot",
    "vendor_boot",
    "vendor_kernel_boot",
    "dtbo",
    "recovery",
    "vbmeta",
    "vbmeta_system",
    "vbmeta_vendor",
];

const REQUIRED_FLASH_BASES: &[&str] = &[
    "super",
    "boot",
    "init_boot",
    "vendor_boot",
    "dtbo",
    "recovery",
    "vbmeta",
    "vbmeta_system",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyMode {
    Full,
    Sampled,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlashPlanEntry {
    pub label: String,
    pub base_label: String,
    pub image_path: String,
    pub image_name: String,
    pub image_size: u64,
    pub image_sectors: u64,
    pub image_sha256: String,
    pub lun: u8,
    pub start_sector: u64,
    pub declared_num_sectors: u64,
    pub sector_size: u64,
    pub source_xml: String,
    pub verify_mode: VerifyMode,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlashPlan {
    pub profile: String,
    pub target_build: String,
    pub firmware_dir: String,
    pub prepared_dir: String,
    pub rawprogram_xmls: Vec<String>,
    pub entries: Vec<FlashPlanEntry>,
    pub erase_after_flash: Vec<String>,
    pub protected_partitions: Vec<String>,
    pub skipped_protected: Vec<String>,
    pub skipped_slot_b: Vec<String>,
    pub skipped_not_allowlisted: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn build_flash_plan(firmware_dir: &Path, prepared_dir: &Path) -> Result<FlashPlan> {
    let analysis = tb376::analyze_tb390_firmware(firmware_dir)?;
    let path_text = firmware_dir.display().to_string();
    if !analysis
        .firmware_fingerprint
        .contains(EXPECTED_TARGET_BUILD)
        && !path_text.contains(EXPECTED_TARGET_BUILD)
    {
        return Err(LtboxError::Patch(format!(
            "firmware is not pinned target build {EXPECTED_TARGET_BUILD}: {}",
            analysis.firmware_fingerprint
        )));
    }

    let modified_vendor_boot = prepared_dir.join("vendor_boot.img");
    let modified_vbmeta = prepared_dir.join("vbmeta.img");
    require_file(&modified_vendor_boot)?;
    require_file(&modified_vbmeta)?;

    let rawprograms = rawprogram_paths(firmware_dir)?;
    let rawprogram_refs: Vec<&Path> = rawprograms.iter().map(PathBuf::as_path).collect();
    let catalog = XmlCatalog::from_paths(&rawprogram_refs)?;

    let protected: HashSet<String> = PROTECTED_PARTITIONS
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let allowed: HashSet<String> = FLASH_ALLOWLIST
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    let mut entries = Vec::new();
    let mut seen_entries = HashSet::new();
    let mut skipped_protected = BTreeSet::new();
    let mut skipped_slot_b = BTreeSet::new();
    let mut skipped_not_allowlisted = BTreeSet::new();

    for record in catalog.records() {
        if record.filename.trim().is_empty() {
            continue;
        }

        let label = record.label.trim();
        let base = record.base_label().to_ascii_lowercase();
        if protected.contains(&base) {
            skipped_protected.insert(label.to_string());
            continue;
        }
        if record.slot_suffix() == Some("_b") {
            skipped_slot_b.insert(label.to_string());
            continue;
        }
        if !allowed.contains(&base) {
            skipped_not_allowlisted.insert(label.to_string());
            continue;
        }

        let lun_u64 =
            parse_required_number(record.lun.as_deref(), "physical_partition_number", label)?;
        let lun = u8::try_from(lun_u64)
            .map_err(|_| LtboxError::Config(format!("{label}: invalid LUN {lun_u64}")))?;
        let start_sector =
            parse_required_number(record.start_sector.as_deref(), "start_sector", label)?;
        let declared_num_sectors = parse_required_number(
            record.num_sectors.as_deref(),
            "num_partition_sectors",
            label,
        )?;
        let sector_size = match record.sector_size_bytes.as_deref() {
            Some(value) => parse_number(value).ok_or_else(|| {
                LtboxError::Config(format!("{label}: invalid SECTOR_SIZE_IN_BYTES {value}"))
            })?,
            None => SECTOR_SIZE,
        };
        if sector_size != SECTOR_SIZE {
            return Err(LtboxError::Config(format!(
                "{label}: expected {SECTOR_SIZE}-byte sectors, XML reports {sector_size}"
            )));
        }

        let image = match base.as_str() {
            "vendor_boot" => modified_vendor_boot.clone(),
            "vbmeta" => modified_vbmeta.clone(),
            _ => firmware_dir.join(record.filename.trim()),
        };
        require_file(&image)?;
        let image_size = fs::metadata(&image)?.len();
        if image_size == 0 {
            return Err(LtboxError::Patch(format!(
                "{label}: image is empty: {}",
                image.display()
            )));
        }
        let image_sectors = image_size.div_ceil(sector_size);
        if image_sectors > declared_num_sectors {
            return Err(LtboxError::Patch(format!(
                "{label}: image spans {image_sectors} sectors but XML allows {declared_num_sectors}"
            )));
        }

        let image_sha256 = sha256_file(&image)?;
        let dedupe_key = format!(
            "{lun}:{start_sector}:{label}:{}:{image_sha256}",
            image.display()
        );
        if !seen_entries.insert(dedupe_key) {
            continue;
        }

        entries.push(FlashPlanEntry {
            label: label.to_string(),
            base_label: base.clone(),
            image_path: image.display().to_string(),
            image_name: image
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_string(),
            image_size,
            image_sectors,
            image_sha256,
            lun,
            start_sector,
            declared_num_sectors,
            sector_size,
            source_xml: record.source_xml.clone(),
            verify_mode: if base == "super" {
                VerifyMode::Sampled
            } else {
                VerifyMode::Full
            },
        });
    }

    let present_bases: BTreeSet<&str> = entries
        .iter()
        .map(|entry| entry.base_label.as_str())
        .collect();
    for required in REQUIRED_FLASH_BASES {
        if !present_bases.contains(required) {
            return Err(LtboxError::Patch(format!(
                "required flash partition is absent from the plan: {required}"
            )));
        }
    }

    entries.sort_by_key(|entry| {
        (
            flash_priority(&entry.base_label),
            entry.lun,
            entry.start_sector,
        )
    });

    Ok(FlashPlan {
        profile: tb376::PROFILE_NAME.to_string(),
        target_build: EXPECTED_TARGET_BUILD.to_string(),
        firmware_dir: firmware_dir.display().to_string(),
        prepared_dir: prepared_dir.display().to_string(),
        rawprogram_xmls: rawprograms
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        entries,
        erase_after_flash: vec!["metadata".to_string(), "userdata".to_string()],
        protected_partitions: PROTECTED_PARTITIONS
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
        skipped_protected: skipped_protected.into_iter().collect(),
        skipped_slot_b: skipped_slot_b.into_iter().collect(),
        skipped_not_allowlisted: skipped_not_allowlisted.into_iter().collect(),
        warnings: vec![
            "The plan deliberately preserves TB376FC ABL/XBL and all Qualcomm firmware partitions.".to_string(),
            "Patch XML and GPT writes are deliberately excluded; device GPT geometry is validated at runtime.".to_string(),
            "Only slot A and unsuffixed Android OS partitions are written; slot B is preserved, but shared super means it is not guaranteed bootable.".to_string(),
            "metadata and userdata are erased after the OS images are written; FRP is preserved.".to_string(),
            "Never relock after this cross-flash.".to_string(),
        ],
    })
}

pub fn write_flash_plan(plan: &FlashPlan, output: &Path) -> Result<()> {
    fs::write(output, serde_json::to_vec_pretty(plan)?)?;
    Ok(())
}

pub fn validate_programmer(loader: &Path) -> Result<String> {
    require_file(loader)?;
    let hash = sha256_file(loader)?;
    if !hash.eq_ignore_ascii_case(EXPECTED_PROGRAMMER_SHA256) {
        return Err(LtboxError::Patch(format!(
            "unexpected Firehose programmer SHA-256 {hash}; expected {EXPECTED_PROGRAMMER_SHA256}"
        )));
    }
    Ok(hash)
}

pub fn sha256_file(path: &Path) -> Result<String> {
    const HASH_BUFFER_BYTES: usize = 1024 * 1024;

    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_BUFFER_BYTES];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02X}");
    }
    Ok(output)
}

fn rawprogram_paths(firmware_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(firmware_dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if path.is_file() && lower.starts_with("rawprogram") && lower.ends_with(".xml") {
            paths.push(path);
        }
    }
    paths.sort_by(|a, b| {
        a.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .cmp(b.file_name().and_then(|name| name.to_str()).unwrap_or(""))
    });
    if paths.is_empty() {
        return Err(LtboxError::FileNotFound(format!(
            "no rawprogram*.xml in {}",
            firmware_dir.display()
        )));
    }
    Ok(paths)
}

fn parse_required_number(value: Option<&str>, field: &str, label: &str) -> Result<u64> {
    let value = value.ok_or_else(|| LtboxError::Config(format!("{label}: missing {field}")))?;
    parse_number(value).ok_or_else(|| {
        LtboxError::Config(format!("{label}: unsupported {field} expression {value}"))
    })
}

fn parse_number(value: &str) -> Option<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn flash_priority(base: &str) -> u8 {
    match base {
        "super" => 10,
        "vbmeta_system" | "vbmeta_vendor" => 20,
        "recovery" => 30,
        "dtbo" => 40,
        "vendor_kernel_boot" => 50,
        "init_boot" => 60,
        "boot" => 70,
        "vendor_boot" => 80,
        "vbmeta" => 90,
        _ => 100,
    }
}

fn require_file(path: &Path) -> Result<()> {
    if !path.is_file() {
        return Err(LtboxError::FileNotFound(path.display().to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_parser_rejects_firehose_expressions() {
        assert_eq!(parse_number("1234"), Some(1234));
        assert_eq!(parse_number("0x10"), Some(16));
        assert_eq!(parse_number("NUM_DISK_SECTORS-34"), None);
        assert_eq!(parse_number("-1"), None);
    }

    #[test]
    fn bootloader_and_device_state_are_not_allowlisted() {
        for label in ["abl", "xbl", "tz", "modem", "persist", "devinfo", "frp"] {
            assert!(!FLASH_ALLOWLIST.contains(&label));
        }
    }

    #[test]
    fn top_level_vbmeta_is_flashed_last() {
        assert!(flash_priority("vbmeta") > flash_priority("vendor_boot"));
        assert!(flash_priority("vendor_boot") > flash_priority("super"));
    }
}
