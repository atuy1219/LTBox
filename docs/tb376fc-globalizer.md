# TB376FC → TB390FU globalizer

This fork contains an experimental tool for one fixed cross-flash profile:

- device: Lenovo TB376FC (`product=malbec`)
- hardware board: `SM8735P_8+128_22`
- source hardware region: PRC
- target firmware: TB390FU ROW `18.0.10.335`
- bootloader state: officially unlocked
- Firehose programmer SHA-256:
  `9C487295ADDBF008024E4D46EEFDFD6F79665BF95F332435361D2102FFDCA162`

It is not a generic Lenovo cross-flasher. Every write is derived from a fixed
allowlist and checked against the connected device GPT before Firehose receives
any program command.

## Build

The dedicated GitHub Actions workflow produces a Windows x64 executable named
`tb376-globalizer-win-x64.exe`.

For a local build:

```text
cargo build --release -p ltbox-gui --example tb376-globalizer
```

The executable is written to:

```text
target/release/examples/tb376-globalizer.exe
```

## Offline analysis and image preparation

```text
tb376-globalizer analyze <TB390FU image folder>
tb376-globalizer prepare <TB390FU image folder> <prepared folder>
tb376-globalizer plan <TB390FU image folder> <prepared folder> <plan.json>
```

`analyze` checks the model fingerprint, the supported root FDT
`region,country` values, required images, AVB public-key SHA-1, image hashes and
rollback metadata present in the package. It requires exactly three supported
FDTs: two whose root `compatible` list contains `qcom,tuna` and one containing
`qcom,tunap`. All three must report `ROW`.

`prepare` creates:

- `vendor_boot.img` with only those three root FDT `region,country` values
  changed from `ROW\0` to `PRC\0`; unrelated strings, including the AVB
  fingerprint suffix, are left unchanged;
- `tb376fc-crossflash-manifest.json`;
- `DO_NOT_RELOCK.txt`.

It does **not** create or modify `vbmeta.img`. The flash plan uses the official
ROW `vbmeta.img` directly from the ROM directory.

The region patch requires exactly three replacements and exactly nine changed
bytes, preserves the image size, and reparses the output before accepting it.

`plan` parses `rawprogram*.xml`, but allows only these Android partitions:

```text
super
boot_a
init_boot_a
vendor_boot_a
vendor_kernel_boot_a (when present)
dtbo_a
recovery_a
vbmeta_a
vbmeta_system_a
vbmeta_vendor_a (when present)
```

Unsuffixed forms are accepted where the device GPT uses them. Slot B, patch XML,
GPT writes, ABL/XBL and Qualcomm firmware are excluded.

## Fastboot preflight

Run this while the same TB376FC is in Fastboot mode:

```text
tb376-globalizer preflight C:\path\to\preflight.json
```

The command refuses to continue unless Fastboot reports:

- `product=malbec`;
- `modelname=TB376FC`;
- `hwboardid` containing `SM8735P_8+128_22`;
- `unlocked=yes`;
- current slot A.

It saves the serial number, raw `getvar all` output and device rollback floors.
The flash command accepts a preflight report for six hours only.

## EDL flash

Keep a full EDL backup outside the working firmware directory. Put the same
device into Qualcomm 9008/EDL, then run:

```text
tb376-globalizer flash \
  <TB390FU image folder> \
  <prepared folder> \
  <xbl_s_devprg_ns.melf> \
  <preflight.json> \
  <backup root> \
  TB376FC-TO-TB390FU-I-HAVE-FULL-BACKUP
```

The flasher performs these steps:

1. Revalidates the pinned target build and fixed AVB key.
2. Verifies the Firehose programmer SHA-256.
3. Compares target rollback indices with the Fastboot preflight floors.
4. Opens Sahara/Firehose and scans GPT on UFS LUNs 0–5.
5. Checks every XML write range is contained inside the exact device partition.
6. Backs up all small target partitions and `metadata` before writing.
7. Writes `super` first, boot-chain Android images next and the official,
   byte-for-byte unmodified ROW `vbmeta` last.
8. Performs full read-back verification for normal images and head/tail sampling
   for split `super` chunks.
9. Erases `metadata` and `userdata` while preserving FRP.
10. Selects slot A and resets only after all checks succeed.

If any write or verification fails, the program does not reset the device. It
leaves the tablet in EDL and points to the session log and backup directory.

## Partitions that are never written

At minimum, the following are protected:

```text
proinfo
persist
modemst1
modemst2
fsg
fsc
frp
lenovolock
devinfo
keystore
```

The allowlist also excludes ABL, XBL, TZ, modem, Bluetooth/DSP firmware and all
other low-level TB376FC firmware. The CN hardware boot chain and hardware region
remain intact.

## Verified AVB configuration

Hardware testing established one bootable configuration:

```text
vendor_boot_a  ROW image with exactly three root region,country values patched to PRC
vbmeta_a       official ROW image from the same target build, completely unmodified
```

Changing official ROW vbmeta flags from 0 to 3, damaging its signature, or
generating an unsigned algorithm-NONE vbmeta made the slot immediately
unbootable (`slot-unbootable: yes`, `slot-successful: no`). Consequently the
TB376FC flow never changes vbmeta flags, never creates unsigned vbmeta, and
never takes vbmeta from the prepared directory. Generic LTBox AVB tooling used
by other device flows is unaffected.

The modified `vendor_boot.img` is only supported with an officially unlocked
bootloader. The bootloader must never be relocked.

**Never relock after installing modified or cross-model firmware images.**
