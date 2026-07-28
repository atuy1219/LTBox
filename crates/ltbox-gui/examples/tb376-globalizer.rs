use ltbox_device::edl::{EdlSession, GptPartitionInfo};
use ltbox_device::fastboot::FastbootDevice;
use ltbox_patch::tb376;
use ltbox_patch::tb376_flash::{self, FlashPlan, FlashPlanEntry, VerifyMode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type CliResult<T> = Result<T, String>;

const PREFLIGHT_MAX_AGE_SECONDS: u64 = 6 * 60 * 60;
const SAMPLE_VERIFY_SECTORS: u64 = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreflightReport {
    generated_at_unix: u64,
    serialno: String,
    product: String,
    modelname: String,
    hwboardid: String,
    unlocked: String,
    current_slot: String,
    rollback_indices: BTreeMap<u32, u64>,
    raw_getvar_all: String,
}

#[derive(Debug, Clone, Serialize)]
struct BackupRecord {
    label: String,
    lun: u8,
    start_sector: u64,
    num_sectors: u64,
    size_bytes: u64,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct FlashResult {
    completed_at_unix: u64,
    profile: String,
    target_build: String,
    serialno: String,
    programmer_sha256: String,
    completed_entries: Vec<String>,
    erased_partitions: Vec<String>,
    backup_records: Vec<BackupRecord>,
    warnings: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> CliResult<()> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(command) = args.next() else {
        print_usage();
        return Err("missing command".to_string());
    };

    match command.to_string_lossy().as_ref() {
        "analyze" => {
            let firmware_dir = next_path(&mut args, "firmware directory")?;
            reject_extra_args(args)?;
            let report = tb376::analyze_tb390_firmware(&firmware_dir)
                .map_err(|error| format!("analyze {}: {error}", firmware_dir.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
        }
        "prepare" => {
            let firmware_dir = next_path(&mut args, "firmware directory")?;
            let output_dir = next_path(&mut args, "output directory")?;
            reject_extra_args(args)?;
            let manifest = tb376::prepare_tb376_crossflash_images(&firmware_dir, &output_dir)
                .map_err(|error| format!("prepare images: {error}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?
            );
            eprintln!("Preparation complete. No device was flashed.");
        }
        "plan" => {
            let firmware_dir = next_path(&mut args, "firmware directory")?;
            let prepared_dir = next_path(&mut args, "prepared directory")?;
            let output_json = next_path(&mut args, "output JSON")?;
            reject_extra_args(args)?;
            let plan = tb376_flash::build_flash_plan(&firmware_dir, &prepared_dir)
                .map_err(|error| format!("build flash plan: {error}"))?;
            tb376_flash::write_flash_plan(&plan, &output_json)
                .map_err(|error| format!("write {}: {error}", output_json.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&plan).map_err(|error| error.to_string())?
            );
        }
        "preflight" => {
            let output_json = next_path(&mut args, "preflight output JSON")?;
            reject_extra_args(args)?;
            let report = fastboot_preflight()?;
            write_json(&output_json, &report)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            eprintln!("Preflight passed. Put this same device into EDL before running flash.");
        }
        "flash" => {
            let firmware_dir = next_path(&mut args, "firmware directory")?;
            let prepared_dir = next_path(&mut args, "prepared directory")?;
            let loader = next_path(&mut args, "Firehose loader")?;
            let preflight_json = next_path(&mut args, "preflight JSON")?;
            let backup_root = next_path(&mut args, "backup root")?;
            let confirmation = next_text(&mut args, "confirmation phrase")?;
            reject_extra_args(args)?;
            if confirmation != tb376_flash::FLASH_CONFIRMATION {
                return Err(format!(
                    "confirmation mismatch; expected exactly: {}",
                    tb376_flash::FLASH_CONFIRMATION
                ));
            }
            flash_device(
                &firmware_dir,
                &prepared_dir,
                &loader,
                &preflight_json,
                &backup_root,
            )?;
        }
        "help" | "--help" | "-h" => print_usage(),
        other => {
            print_usage();
            return Err(format!("unknown command: {other}"));
        }
    }

    Ok(())
}

fn fastboot_preflight() -> CliResult<PreflightReport> {
    let mut device = FastbootDevice::open().map_err(|error| format!("open Fastboot: {error}"))?;
    let serialno = required_getvar(&mut device, "serialno")?;
    let product = required_getvar(&mut device, "product")?;
    let modelname = required_getvar(&mut device, "modelname")?;
    let hwboardid = required_getvar(&mut device, "hwboardid")?;
    let unlocked = required_getvar(&mut device, "unlocked")?;
    let current_slot = required_getvar(&mut device, "current-slot")?;
    let vars = device
        .get_all_vars()
        .map_err(|error| format!("Fastboot getvar all: {error}"))?;

    if !product.eq_ignore_ascii_case(tb376::DEVICE_PRODUCT) {
        return Err(format!(
            "wrong product: {product}; expected {}",
            tb376::DEVICE_PRODUCT
        ));
    }
    if !modelname.eq_ignore_ascii_case(tb376::SOURCE_MODEL) {
        return Err(format!(
            "wrong model: {modelname}; expected {}",
            tb376::SOURCE_MODEL
        ));
    }
    if !hwboardid.contains(tb376::DEVICE_HWBOARD_ID) {
        return Err(format!(
            "wrong hwboardid: {hwboardid}; expected to contain {}",
            tb376::DEVICE_HWBOARD_ID
        ));
    }
    if !matches!(unlocked.to_ascii_lowercase().as_str(), "yes" | "true" | "1") {
        return Err(format!("bootloader is not unlocked: {unlocked}"));
    }
    if !matches!(current_slot.to_ascii_lowercase().as_str(), "a" | "_a") {
        return Err(format!(
            "current slot must be A before this fixed profile is used: {current_slot}"
        ));
    }
    if serialno.len() < 8 {
        return Err(format!("unexpected serial number: {serialno}"));
    }

    Ok(PreflightReport {
        generated_at_unix: unix_now()?,
        serialno,
        product,
        modelname,
        hwboardid,
        unlocked,
        current_slot,
        rollback_indices: vars.rollback_indices.into_iter().collect(),
        raw_getvar_all: vars.raw_getvar_all,
    })
}

fn flash_device(
    firmware_dir: &Path,
    prepared_dir: &Path,
    loader: &Path,
    preflight_json: &Path,
    backup_root: &Path,
) -> CliResult<()> {
    let preflight: PreflightReport = read_json(preflight_json)?;
    validate_preflight_report(&preflight)?;

    let programmer_sha256 = tb376_flash::validate_programmer(loader)
        .map_err(|error| format!("validate Firehose loader: {error}"))?;

    let preparation = tb376::prepare_tb376_crossflash_images(firmware_dir, prepared_dir)
        .map_err(|error| format!("prepare modified images: {error}"))?;
    validate_rollback_floors(&preflight, &preparation.analysis)?;

    let plan = tb376_flash::build_flash_plan(firmware_dir, prepared_dir)
        .map_err(|error| format!("build flash plan: {error}"))?;
    let plan_path = prepared_dir.join("tb376fc-flash-plan.json");
    tb376_flash::write_flash_plan(&plan, &plan_path)
        .map_err(|error| format!("write flash plan: {error}"))?;

    let session_dir = backup_root.join(format!("tb376fc-before-row-{}", unix_now()?));
    std::fs::create_dir_all(&session_dir)
        .map_err(|error| format!("create backup directory {}: {error}", session_dir.display()))?;
    write_json(&session_dir.join("preflight.json"), &preflight)?;
    write_json(&session_dir.join("flash-plan.json"), &plan)?;
    write_json(
        &session_dir.join("firmware-analysis.json"),
        &preparation.analysis,
    )?;
    std::fs::write(
        session_dir.join("DO_NOT_RELOCK.txt"),
        "TB376FC officially unlocked cross-flash backup. Never relock after installing modified or TB390FU images.\n",
    )
    .map_err(|error| error.to_string())?;

    let mut log = vec![
        format!("[TB376] profile={}", plan.profile),
        format!("[TB376] serial={}", preflight.serialno),
        format!("[TB376] target_build={}", plan.target_build),
        format!("[TB376] programmer_sha256={programmer_sha256}"),
        format!("[TB376] backup_dir={}", session_dir.display()),
        "[TB376] waiting for Qualcomm 9008 / EDL".to_string(),
    ];

    let result = flash_device_inner(
        loader,
        &preflight,
        &plan,
        &session_dir,
        &programmer_sha256,
        &mut log,
    );
    let log_path = session_dir.join("flash.log");
    let _ = std::fs::write(&log_path, format!("{}\n", log.join("\n")));

    match result {
        Ok(()) => {
            println!("Flash completed. Log: {}", log_path.display());
            Ok(())
        }
        Err(error) => Err(format!(
            "{error}\nThe device was intentionally left in EDL. Do not reset until the log is reviewed: {}",
            log_path.display()
        )),
    }
}

fn flash_device_inner(
    loader: &Path,
    preflight: &PreflightReport,
    plan: &FlashPlan,
    session_dir: &Path,
    programmer_sha256: &str,
    log: &mut Vec<String>,
) -> CliResult<()> {
    let mut session = EdlSession::open(loader, false, log)
        .map_err(|error| format!("open EDL session: {error}"))?;
    let partitions = session
        .scan_partitions(0..=5, log)
        .map_err(|error| format!("scan device GPT: {error}"))?;
    validate_device_geometry(plan, &partitions)?;

    let backup_records =
        backup_small_partitions(&mut session, plan, &partitions, session_dir, log)?;
    write_json(&session_dir.join("backup-manifest.json"), &backup_records)?;
    std::fs::write(
        session_dir.join("SUPER_NOT_BACKED_UP.txt"),
        "The super partition was not duplicated by this run because it is multi-gigabyte. Keep the existing full EDL backup before continuing.\n",
    )
    .map_err(|error| error.to_string())?;

    let mut completed_entries = Vec::new();
    for entry in &plan.entries {
        let partition = find_partition(&partitions, &entry.label, entry.lun)?;
        let partition_end = partition
            .start_sector
            .checked_add(partition.num_sectors)
            .ok_or_else(|| format!("{} GPT range overflow", entry.label))?;
        let remaining = partition_end
            .checked_sub(entry.start_sector)
            .ok_or_else(|| format!("{} start lies before/after GPT partition", entry.label))?;

        session
            .flash_partition_at(
                &entry.label,
                Path::new(&entry.image_path),
                entry.lun,
                &entry.start_sector.to_string(),
                remaining,
                log,
            )
            .map_err(|error| format!("flash {}: {error}", entry.label))?;
        verify_entry(&mut session, entry, session_dir, log)?;
        completed_entries.push(format!(
            "{}@LUN{}:{} <- {}",
            entry.label, entry.lun, entry.start_sector, entry.image_name
        ));
    }

    let mut erased_partitions = Vec::new();
    for label in &plan.erase_after_flash {
        let partition = find_unique_partition(&partitions, label)?;
        let sectors = usize::try_from(partition.num_sectors)
            .map_err(|_| format!("{label} sector count exceeds host usize"))?;
        session
            .erase_partition_at(
                label,
                partition.lun,
                &partition.start_sector.to_string(),
                sectors,
                log,
            )
            .map_err(|error| format!("erase {label}: {error}"))?;
        erased_partitions.push(label.clone());
    }

    session
        .set_active_slot_a(log)
        .map_err(|error| format!("set active slot A: {error}"))?;

    let result = FlashResult {
        completed_at_unix: unix_now()?,
        profile: plan.profile.clone(),
        target_build: plan.target_build.clone(),
        serialno: preflight.serialno.clone(),
        programmer_sha256: programmer_sha256.to_string(),
        completed_entries,
        erased_partitions,
        backup_records,
        warnings: vec![
            "Slot B and all TB376FC low-level firmware were preserved.".to_string(),
            "The first boot must remain unlocked; never relock.".to_string(),
        ],
    };
    write_json(&session_dir.join("flash-result.json"), &result)?;
    log.push("[TB376] all writes and verification completed; resetting device".to_string());
    session.reset_tolerant(log);
    Ok(())
}

fn validate_preflight_report(report: &PreflightReport) -> CliResult<()> {
    let now = unix_now()?;
    if report.generated_at_unix > now {
        return Err("preflight timestamp is in the future".to_string());
    }
    let age = now - report.generated_at_unix;
    if age > PREFLIGHT_MAX_AGE_SECONDS {
        return Err(format!(
            "preflight is {age} seconds old; rerun it immediately before flashing"
        ));
    }
    if !report.product.eq_ignore_ascii_case(tb376::DEVICE_PRODUCT)
        || !report.modelname.eq_ignore_ascii_case(tb376::SOURCE_MODEL)
        || !report.hwboardid.contains(tb376::DEVICE_HWBOARD_ID)
    {
        return Err("preflight does not describe the fixed TB376FC malbec profile".to_string());
    }
    if !matches!(
        report.unlocked.to_ascii_lowercase().as_str(),
        "yes" | "true" | "1"
    ) {
        return Err("preflight says the bootloader is locked".to_string());
    }
    if !matches!(
        report.current_slot.to_ascii_lowercase().as_str(),
        "a" | "_a"
    ) {
        return Err("preflight current slot is not A".to_string());
    }
    Ok(())
}

fn validate_rollback_floors(
    report: &PreflightReport,
    analysis: &tb376::FirmwareAnalysis,
) -> CliResult<()> {
    for image in &analysis.images {
        let location = image.rollback_index_location;
        if let Some(floor) = report.rollback_indices.get(&location)
            && image.rollback_index < *floor
        {
            return Err(format!(
                "rollback refusal: {} index {} at location {} is below device floor {}",
                image.name, image.rollback_index, location, floor
            ));
        }
    }
    Ok(())
}

fn validate_device_geometry(plan: &FlashPlan, partitions: &[GptPartitionInfo]) -> CliResult<()> {
    for entry in &plan.entries {
        let partition = find_partition(partitions, &entry.label, entry.lun)?;
        let partition_end = partition
            .start_sector
            .checked_add(partition.num_sectors)
            .ok_or_else(|| format!("{} GPT range overflow", entry.label))?;
        let image_end = entry
            .start_sector
            .checked_add(entry.image_sectors)
            .ok_or_else(|| format!("{} image range overflow", entry.label))?;
        if entry.start_sector < partition.start_sector || image_end > partition_end {
            return Err(format!(
                "{} XML/image range {}..{} escapes device GPT range {}..{} on LUN {}",
                entry.label,
                entry.start_sector,
                image_end,
                partition.start_sector,
                partition_end,
                entry.lun
            ));
        }
    }

    for protected in &plan.protected_partitions {
        if plan
            .entries
            .iter()
            .any(|entry| entry.base_label.eq_ignore_ascii_case(protected))
        {
            return Err(format!(
                "protected partition leaked into flash plan: {protected}"
            ));
        }
    }
    Ok(())
}

fn backup_small_partitions(
    session: &mut EdlSession,
    plan: &FlashPlan,
    partitions: &[GptPartitionInfo],
    session_dir: &Path,
    log: &mut Vec<String>,
) -> CliResult<Vec<BackupRecord>> {
    let backup_dir = session_dir.join("partitions");
    std::fs::create_dir_all(&backup_dir).map_err(|error| error.to_string())?;

    let mut labels = BTreeSet::new();
    for entry in &plan.entries {
        if entry.base_label != "super" {
            labels.insert((entry.label.clone(), entry.lun));
        }
    }
    if let Ok(metadata) = find_unique_partition(partitions, "metadata") {
        labels.insert((metadata.name.clone(), metadata.lun));
    }

    let required_bytes = labels.iter().try_fold(0u64, |total, (label, lun)| {
        let partition = find_partition(partitions, label, *lun)?;
        total
            .checked_add(partition.size_bytes)
            .ok_or_else(|| "backup byte count overflow".to_string())
    })?;
    let available = fs2::available_space(&backup_dir)
        .map_err(|error| format!("query backup free space: {error}"))?;
    if available < required_bytes {
        return Err(format!(
            "backup needs {required_bytes} bytes but only {available} bytes are available in {}",
            backup_dir.display()
        ));
    }

    let mut records = Vec::new();
    for (label, lun) in labels {
        let partition = find_partition(partitions, &label, lun)?;
        let output = backup_dir.join(format!("{}-lun{}.img", sanitize_name(&label), lun));
        let sectors = usize::try_from(partition.num_sectors)
            .map_err(|_| format!("{label} sector count exceeds host usize"))?;
        session
            .dump_partition_at(&label, &output, lun, partition.start_sector, sectors, log)
            .map_err(|error| format!("backup {label}: {error}"))?;
        records.push(BackupRecord {
            label,
            lun,
            start_sector: partition.start_sector,
            num_sectors: partition.num_sectors,
            size_bytes: partition.size_bytes,
            path: output.display().to_string(),
            sha256: tb376_flash::sha256_file(&output)
                .map_err(|error| format!("hash backup {}: {error}", output.display()))?,
        });
    }
    Ok(records)
}

fn verify_entry(
    session: &mut EdlSession,
    entry: &FlashPlanEntry,
    session_dir: &Path,
    log: &mut Vec<String>,
) -> CliResult<()> {
    match entry.verify_mode {
        VerifyMode::Full => verify_range(
            session,
            entry,
            0,
            entry.start_sector,
            entry.image_sectors,
            session_dir,
            log,
        ),
        VerifyMode::Sampled => {
            let first = entry.image_sectors.min(SAMPLE_VERIFY_SECTORS);
            verify_range(
                session,
                entry,
                0,
                entry.start_sector,
                first,
                session_dir,
                log,
            )?;
            if entry.image_sectors > first {
                let tail = entry.image_sectors.min(SAMPLE_VERIFY_SECTORS);
                let sector_offset = entry.image_sectors - tail;
                verify_range(
                    session,
                    entry,
                    sector_offset * entry.sector_size,
                    entry.start_sector + sector_offset,
                    tail,
                    session_dir,
                    log,
                )?;
            }
            Ok(())
        }
    }
}

fn verify_range(
    session: &mut EdlSession,
    entry: &FlashPlanEntry,
    image_offset: u64,
    device_start_sector: u64,
    sectors: u64,
    session_dir: &Path,
    log: &mut Vec<String>,
) -> CliResult<()> {
    if sectors == 0 {
        return Ok(());
    }
    let verify_dir = session_dir.join("verify");
    std::fs::create_dir_all(&verify_dir).map_err(|error| error.to_string())?;
    let output = verify_dir.join(format!(
        "{}-lun{}-start{}.img",
        sanitize_name(&entry.label),
        entry.lun,
        device_start_sector
    ));
    let sector_count = usize::try_from(sectors)
        .map_err(|_| format!("verify sector count too large for {}", entry.label))?;
    session
        .dump_partition_at(
            &entry.label,
            &output,
            entry.lun,
            device_start_sector,
            sector_count,
            log,
        )
        .map_err(|error| format!("read-back {}: {error}", entry.label))?;

    let mut source = std::fs::File::open(&entry.image_path)
        .map_err(|error| format!("open source {}: {error}", entry.image_path))?;
    source
        .seek(SeekFrom::Start(image_offset))
        .map_err(|error| format!("seek source {}: {error}", entry.image_path))?;
    let max_bytes = sectors
        .checked_mul(entry.sector_size)
        .ok_or_else(|| "verify byte count overflow".to_string())?;
    let remaining_source = entry.image_size.saturating_sub(image_offset);
    let compare_bytes = remaining_source.min(max_bytes);
    let compare_len = usize::try_from(compare_bytes)
        .map_err(|_| "verify byte count exceeds host usize".to_string())?;

    let mut expected = vec![0u8; compare_len];
    source
        .read_exact(&mut expected)
        .map_err(|error| format!("read source {}: {error}", entry.image_path))?;
    let mut actual_file = std::fs::File::open(&output)
        .map_err(|error| format!("open read-back {}: {error}", output.display()))?;
    let mut actual = vec![0u8; compare_len];
    actual_file
        .read_exact(&mut actual)
        .map_err(|error| format!("read read-back {}: {error}", output.display()))?;
    if expected != actual {
        return Err(format!(
            "read-back verification failed for {} at image offset {}",
            entry.label, image_offset
        ));
    }
    std::fs::remove_file(&output).map_err(|error| error.to_string())?;
    log.push(format!(
        "[Verify] {} offset={} bytes={} OK",
        entry.label, image_offset, compare_bytes
    ));
    Ok(())
}

fn find_partition<'a>(
    partitions: &'a [GptPartitionInfo],
    label: &str,
    lun: u8,
) -> CliResult<&'a GptPartitionInfo> {
    let matches: Vec<&GptPartitionInfo> = partitions
        .iter()
        .filter(|partition| partition.lun == lun && partition.name.eq_ignore_ascii_case(label))
        .collect();
    match matches.as_slice() {
        [partition] => Ok(*partition),
        [] => Err(format!("device GPT has no {label} on LUN {lun}")),
        _ => Err(format!(
            "device GPT has duplicate {label} entries on LUN {lun}"
        )),
    }
}

fn find_unique_partition<'a>(
    partitions: &'a [GptPartitionInfo],
    label: &str,
) -> CliResult<&'a GptPartitionInfo> {
    let matches: Vec<&GptPartitionInfo> = partitions
        .iter()
        .filter(|partition| partition.name.eq_ignore_ascii_case(label))
        .collect();
    match matches.as_slice() {
        [partition] => Ok(*partition),
        [] => Err(format!("device GPT has no {label} partition")),
        _ => Err(format!("device GPT has ambiguous {label} partitions")),
    }
}

fn required_getvar(device: &mut FastbootDevice, name: &str) -> CliResult<String> {
    let value = device
        .getvar(name)
        .map_err(|error| format!("Fastboot getvar {name}: {error}"))?;
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(format!("Fastboot getvar {name} returned empty"))
    } else {
        Ok(value)
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> CliResult<T> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> CliResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    std::fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn unix_now() -> CliResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock before Unix epoch: {error}"))
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn next_path(args: &mut impl Iterator<Item = OsString>, label: &str) -> CliResult<PathBuf> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {label}"))
}

fn next_text(args: &mut impl Iterator<Item = OsString>, label: &str) -> CliResult<String> {
    args.next()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| format!("missing {label}"))
}

fn reject_extra_args(mut args: impl Iterator<Item = OsString>) -> CliResult<()> {
    if let Some(extra) = args.next() {
        return Err(format!("unexpected argument: {}", extra.to_string_lossy()));
    }
    Ok(())
}

fn print_usage() {
    eprintln!(
        "TB376FC -> TB390FU fixed-profile tool\n\
         \n\
         Analysis / preparation:\n\
           tb376-globalizer analyze <TB390FU image folder>\n\
           tb376-globalizer prepare <TB390FU image folder> <prepared folder>\n\
           tb376-globalizer plan <TB390FU image folder> <prepared folder> <plan.json>\n\
         \n\
         Device preflight (run while the officially unlocked TB376FC is in Fastboot):\n\
           tb376-globalizer preflight <preflight.json>\n\
         \n\
         Flash (put the same device in EDL/9008 first):\n\
           tb376-globalizer flash <TB390FU image folder> <prepared folder> \\\n             <xbl_s_devprg_ns.melf> <preflight.json> <backup root> \\\n             {}\n\
         \n\
         The flasher writes only allow-listed Android slot-A/super partitions,\n\
         backs up small target partitions, validates GPT geometry and rollback\n\
         floors, verifies read-back data, erases metadata/userdata, and never\n\
         relocks. On any failure it leaves the device in EDL.",
        tb376_flash::FLASH_CONFIRMATION
    );
}
