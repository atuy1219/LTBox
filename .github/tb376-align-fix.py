from pathlib import Path

path = Path("crates/ltbox-patch/src/tb376.rs")
text = path.read_text()

replacements = [
    (
        "pos = align4_checked(name_end + 1)",
        "pos = align_fdt_offset(name_end + 1, bounds.base)",
    ),
    (
        "pos = align4_checked(value_end).ok_or_else(|| {",
        "pos = align_fdt_offset(value_end, bounds.base).ok_or_else(|| {",
    ),
]

for old, new in replacements:
    if text.count(old) != 1:
        raise SystemExit(f"expected one match for {old!r}, found {text.count(old)}")
    text = text.replace(old, new)

anchor = """fn align4_checked(value: usize) -> Option<usize> {
    value.checked_add(3).map(|aligned| aligned & !3)
}
"""
addition = """fn align_fdt_offset(value: usize, base: usize) -> Option<usize> {
    let relative = value.checked_sub(base)?;
    base.checked_add(align4_checked(relative)?)
}

fn align4_checked(value: usize) -> Option<usize> {
    value.checked_add(3).map(|aligned| aligned & !3)
}
"""
if text.count(anchor) != 1:
    raise SystemExit(f"expected one align helper anchor, found {text.count(anchor)}")
text = text.replace(anchor, addition)
path.write_text(text)
