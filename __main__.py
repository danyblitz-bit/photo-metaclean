"""Photo MetaClean — strip sensitive EXIF/GPS metadata from JPEG/PNG images before sharing."""
import argparse
import struct
import sys
from pathlib import Path

PNG_SIG = b"\x89PNG\r\n\x1a\n"
JPEG_NO_LEN_MARKERS = {0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9}
DROPPED_JPEG = {"EXIF", "XMP", "IPTC", "COMMENT"}
DROPPED_PNG = {"tEXt", "zTXt", "iTXt", "tIME", "eXIf"}

EXIF_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
IFD0_TAGS = {0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x0132: "DateTime", 0x0134: "UpdateTime"}
EXIF_TAGS = {0x9003: "DateTimeOriginal", 0x9011: "OffsetTimeOriginal"}
GPS_TAGS = {0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude", 0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude"}


def u16(v, e=">"):
    return struct.pack(e + "H", v)


def u32(v, e=">"):
    return struct.pack(e + "I", v)


def jpeg_segment_kind(marker: int, payload: bytes):
    if marker == 0xFE:
        return "COMMENT", payload.decode("latin-1", "replace")[:200]
    if marker == 0xE1:
        if payload.startswith(b"Exif\x00\x00"):
            info = decode_exif(payload)
            return ("EXIF", info) if info else None
        if payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            return "XMP", "XMP metadata present"
        return None
    if marker == 0xED and payload.startswith(b"Photoshop 3.0\x00"):
        return "IPTC", "IPTC/Photoshop block present"
    return None


def read_ifd(t: bytes, e: str, off: int) -> dict:
    if off + 2 > len(t):
        return {}
    n = struct.unpack(e + "H", t[off:off + 2])[0]
    entries = {}
    for k in range(n):
        p = off + 2 + k * 12
        if p + 12 > len(t):
            break
        tag, typ, cnt = struct.unpack(e + "HHI", t[p:p + 8])
        entries[tag] = (typ, cnt, t[p + 8:p + 12])
    return entries


def get_value(t: bytes, e: str, typ: int, cnt: int, vb: bytes):
    size = cnt * EXIF_SIZES.get(typ, 1)
    if size <= 4:
        data = vb[:size]
    else:
        off = struct.unpack(e + "I", vb)[0]
        data = t[off:off + size]
    if typ == 2:
        return data.rstrip(b"\x00").decode("latin-1", "replace")
    if typ == 5:
        vals = []
        for i in range(0, len(data) - 7, 8):
            num, den = struct.unpack(e + "II", data[i:i + 8])
            vals.append(num / den if den else 0.0)
        return vals
    return data


def gps_dms(vals, ref):
    if not vals or len(vals) < 2:
        return None
    d = float(vals[0]) + (float(vals[1]) if len(vals) > 1 else 0.0) / 60
    if len(vals) > 2:
        d += float(vals[2]) / 3600
    return f"{d:.5f}{ref}"


def decode_exif(payload: bytes) -> dict:
    t = payload[6:]
    if len(t) < 8:
        return {}
    if t[:2] == b"II":
        e = "<"
    elif t[:2] == b"MM":
        e = ">"
    else:
        return {}
    if t[2:4] not in (b"*\x00", b"\x00*"):
        return {}
    base = struct.unpack(e + "I", t[4:8])[0]
    if base + 2 > len(t):
        return {}
    out = {}
    ifd0 = read_ifd(t, e, base)
    for tag, val in ifd0.items():
        if tag in (0x8769, 0x8825):
            continue
        name = IFD0_TAGS.get(tag)
        if name:
            out[name] = get_value(t, e, val[0], val[1], val[2])
    if 0x8769 in ifd0:
        off = struct.unpack(e + "I", ifd0[0x8769][2])[0]
        for tag, val in read_ifd(t, e, off).items():
            name = EXIF_TAGS.get(tag)
            if name:
                out[name] = get_value(t, e, val[0], val[1], val[2])
    if 0x8825 in ifd0:
        off = struct.unpack(e + "I", ifd0[0x8825][2])[0]
        gps = read_ifd(t, e, off)
        lat = gps_dms(get_value(t, e, *gps[0x0002]) if 0x0002 in gps else None,
                      get_value(t, e, *gps[0x0001]) if 0x0001 in gps else "")
        lon = gps_dms(get_value(t, e, *gps[0x0004]) if 0x0004 in gps else None,
                      get_value(t, e, *gps[0x0003]) if 0x0003 in gps else "")
        if lat or lon:
            out["GPS"] = " ".join(x for x in (lat, lon) if x)
    return out


def read_orientation(payload: bytes):
    """Orientation (IFD0 0x0112) from an APP1 payload, or None."""
    t = payload[6:]
    if len(t) < 8 or t[:2] not in (b"II", b"MM"):
        return None
    e = "<" if t[:2] == b"II" else ">"
    if t[2:4] not in (b"*\x00", b"\x00*"):
        return None
    base = struct.unpack(e + "I", t[4:8])[0]
    entry = read_ifd(t, e, base).get(0x0112)
    if not entry:
        return None
    val = get_value(t, e, entry[0], entry[1], entry[2])
    if not isinstance(val, (bytes, bytearray)) or not val:
        return None
    if len(val) >= 2:
        return struct.unpack(e + "H", val[:2])[0]
    return val[0]


def minimal_exif_app1(orientation: int) -> bytes:
    """APP1 carrying nothing but Orientation: display rotation survives, pixels stay untouched."""
    tiff = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 1)
    tiff += struct.pack("<HHI", 0x0112, 3, 1) + struct.pack("<H", orientation) + b"\x00\x00"
    tiff += struct.pack("<I", 0)
    return b"Exif\x00\x00" + tiff


def parse_jpeg(raw: bytes):
    found = []
    if raw[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG (missing SOI marker)")
    kept = bytearray(b"\xff\xd8")
    i = 2
    while i < len(raw):
        if raw[i] != 0xFF:
            break
        marker = raw[i + 1]
        if marker == 0xDA:  # SOS: entropy-coded data runs to EOI, copy verbatim
            length = struct.unpack(">H", raw[i + 2:i + 4])[0]
            kept += raw[i:i + 2 + length]
            i += 2 + length
            eoi = raw.find(b"\xff\xd9", i)
            kept += raw[i:eoi + 2] if eoi != -1 else raw[i:]
            break
        if marker not in JPEG_NO_LEN_MARKERS:
            length = struct.unpack(">H", raw[i + 2:i + 4])[0]
            payload = raw[i + 4:i + 2 + length]
            kind_desc = jpeg_segment_kind(marker, payload)
            if kind_desc:
                found.append(kind_desc)
                if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
                    orientation = read_orientation(payload)
                    if orientation and orientation != 1:
                        kept += jpeg_seg(0xE1, minimal_exif_app1(orientation))
            else:
                kept += raw[i:i + 2 + length]
            i += 2 + length
        elif marker == 0xD9:
            kept += b"\xff\xd9"
            kept += raw[i + 2:]
            break
        else:
            kept += raw[i:i + 2]
            i += 2
    return bytes(kept), found


def png_segment_desc(typ: str, data: bytes):
    if typ == "tEXt":
        kw, _, text = data.partition(b"\x00")
        return f"{kw.decode('latin-1', 'replace')}: {text.decode('latin-1', 'replace')[:200]}"
    if typ == "zTXt":
        kw = data.split(b"\x00", 1)[0]
        return f"{kw.decode('latin-1', 'replace')} (compressed text)"
    if typ == "iTXt":
        kw = data.split(b"\x00", 1)[0]
        return f"{kw.decode('latin-1', 'replace')} (international text)"
    if typ == "tIME":
        y, mo, d, h, mi, s = struct.unpack(">HBBBBB", data[:7])
        return f"Modified {y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}"
    if typ == "eXIf":
        return "embedded EXIF chunk"
    return typ


def parse_png(raw: bytes):
    found = []
    if raw[:8] != PNG_SIG:
        raise ValueError("not a PNG (missing signature)")
    kept = bytearray(raw[:8])
    i = 8
    while i + 8 <= len(raw):
        length = struct.unpack(">I", raw[i:i + 4])[0]
        typ = raw[i + 4:i + 8].decode("latin-1")
        seg = raw[i:i + 12 + length]
        if typ == "IEND":
            kept += seg
            kept += raw[i + 12 + length:]
            break
        if typ in DROPPED_PNG:
            found.append((typ, png_segment_desc(typ, raw[i + 8:i + 8 + length])))
        else:
            kept += seg
        i += 12 + length
    return bytes(kept), found


def audit(path: Path) -> dict:
    raw = path.read_bytes()
    if raw[:2] == b"\xff\xd8":
        meta = parse_jpeg(raw)[1]
        fmt = "JPEG"
    elif raw[:8] == PNG_SIG:
        meta = parse_png(raw)[1]
        fmt = "PNG"
    else:
        raise ValueError("unsupported format (only JPEG/PNG)")
    return {"format": fmt, "has_metadata": bool(meta), "metadata": meta}


def clean(path: Path, out: Path) -> dict:
    raw = path.read_bytes()
    if raw[:2] == b"\xff\xd8":
        cleaned, _ = parse_jpeg(raw)
    elif raw[:8] == PNG_SIG:
        cleaned, _ = parse_png(raw)
    else:
        raise ValueError("unsupported format (only JPEG/PNG)")
    out.write_bytes(cleaned)
    return {"cleaned": True, "input_bytes": len(raw), "output_bytes": len(cleaned), "saved_bytes": len(raw) - len(cleaned)}


def fmt(v: int) -> str:
    return f"{v/1024:.1f} KB"


def jpeg_seg(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes([marker]) + u16(2 + len(payload)) + payload


def build_exif_app1() -> bytes:
    # TIFF little-endian: base=8, IFD0 at 8 with 4 entries (10..57), next at 58,
    # Exif IFD at 62 (1 entry -> 64..75), GPS IFD at 80 (4 entries -> 82..129),
    # value region at 134: DateTimeOriginal, GPS latitude, GPS longitude.
    def e2(x):
        return struct.pack("<H", x)

    def e4(x):
        return struct.pack("<I", x)

    base, exif_off, gps_off, data_off = 8, 62, 80, 134

    def ent(tag, typ, cnt, val):
        return struct.pack("<HHI", tag, typ, cnt) + val

    IFD0 = struct.pack("<H", 4)
    IFD0 += ent(0x010F, 2, 3, b"Can\x00")
    IFD0 += ent(0x0110, 2, 2, b"X7\x00\x00")
    IFD0 += ent(0x8769, 4, 1, e4(exif_off))
    IFD0 += ent(0x8825, 4, 1, e4(gps_off))
    IFD0 += e4(0)

    EXIF_IFD = struct.pack("<H", 1)
    EXIF_IFD += ent(0x9003, 2, 20, e4(data_off))
    EXIF_IFD += e4(0)

    GPS_IFD = struct.pack("<H", 4)
    GPS_IFD += ent(0x0001, 2, 1, b"N\x00\x00\x00")
    GPS_IFD += ent(0x0002, 5, 3, e4(data_off + 20))
    GPS_IFD += ent(0x0003, 2, 1, b"W\x00\x00\x00")
    GPS_IFD += ent(0x0004, 5, 3, e4(data_off + 44))
    GPS_IFD += e4(0)

    data = b"2024:06:01 12:00:00" + b"\x00"  # pad to exactly 20 bytes per declared ASCII count
    data += b"".join(e4(n) + e4(d) for n, d in [(42, 1), (30, 1), (0, 1)])
    data += b"".join(e4(n) + e4(d) for n, d in [(71, 1), (4, 1), (0, 1)])

    tiff = b"II*\x00" + e4(base) + IFD0
    assert len(tiff) == exif_off, f"IFD0 layout {len(tiff)} != {exif_off}"
    tiff += EXIF_IFD
    tiff += GPS_IFD
    tiff += data
    return b"Exif\x00\x00" + tiff


def self_check() -> int:
    import tempfile

    exif = build_exif_app1()
    jpg = (
        b"\xff\xd8"
        + jpeg_seg(0xE0, b"JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00")
        + jpeg_seg(0xE1, exif)
        + jpeg_seg(0xFE, b"secret comment here")
        + b"\xff\xc0\x00\x11\x08\x00\x08\x00\x08\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"
        + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
        + b"\x1f\xd8\x45\xaa entropy-escaped \xff\x00\xfe data"
        + b"\xff\xd9"
    )
    cleaned, meta = parse_jpeg(jpg)
    kinds = {k for k, _ in meta}
    assert {"EXIF", "COMMENT"} <= kinds, f"missed segments: {kinds}"
    exif_info = dict(meta)["EXIF"]
    assert exif_info.get("Make") == "Can", exif_info
    assert exif_info.get("Model") == "X7", exif_info
    assert exif_info.get("DateTimeOriginal") == "2024:06:01 12:00:00", exif_info
    gps = exif_info.get("GPS", "")
    assert "N" in gps and "W" in gps and "42.5" in gps, gps
    assert b"\xff\xe1" not in cleaned, "EXIF segment survived"
    assert b"secret comment" not in cleaned, "comment survived"
    assert cleaned.endswith(b"\xff\xd9"), "EOI missing"
    assert b"entropy-escaped" in cleaned, "entropy data damaged"
    assert dict(parse_jpeg(cleaned)[1]) == {}, "re-audit not clean"

    # Orientation must survive: dropping APP1 outright turns phone photos sideways.
    rot = (
        b"\xff\xd8"
        + jpeg_seg(0xE1, minimal_exif_app1(6))
        + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
        + b"rotated \xff\x00\xfe data"
        + b"\xff\xd9"
    )
    rot_clean, rot_meta = parse_jpeg(rot)
    assert rot_clean[2:4] == b"\xff\xe1", "orientation segment dropped"
    seg_len = struct.unpack(">H", rot_clean[4:6])[0]
    assert read_orientation(rot_clean[6:6 + seg_len - 2]) == 6, "orientation value lost"
    assert rot_meta == [], rot_meta
    assert parse_jpeg(rot_clean)[1] == [], "orientation-only re-audit not clean"
    assert b"rotated" in rot_clean and rot_clean.endswith(b"\xff\xd9"), "scan data damaged"

    # big-endian TIFF: PIL writes MM, and Orientation must not read back as 0
    be = b"MM\x00\x2a" + struct.pack(">I", 8) + struct.pack(">H", 1)
    be += struct.pack(">HHI", 0x0112, 3, 1) + struct.pack(">HH", 8, 0) + struct.pack(">I", 0)
    assert read_orientation(b"Exif\x00\x00" + be) == 8, "big-endian orientation misread"

    png = (
        PNG_SIG
        + b"\x00\x00\x00\x0dIHDR" + b"\x00\x00\x00\x08\x00\x00\x00\x08\x08\x02\x00\x00\x00" + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x14tEXtComment\x00private info" + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x07tIME\xe8\x07\x05\x0a\x09\x1e\x00" + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x03IDAT" + b"abc" + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00IEND" + b"\x00\x00\x00\x00"
    )
    png_clean, png_meta = parse_png(png)
    assert {k for k, _ in png_meta} == {"tEXt", "tIME"}, png_meta
    assert b"private info" not in png_clean, "tEXt survived"
    assert png_clean[:8] == PNG_SIG and png_clean.endswith(b"IEND\x00\x00\x00\x00")

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        j = d / "shot.jpg"
        j.write_bytes(jpg)
        out = d / "shot_clean.jpg"
        res = clean(j, out)
        assert res["cleaned"] and res["saved_bytes"] > 0
        assert not audit(out)["has_metadata"]
        p = d / "img.png"
        p.write_bytes(png)
        out2 = d / "img_clean.png"
        res2 = clean(p, out2)
        assert res2["cleaned"]
        assert not audit(out2)["has_metadata"]
    print("self-check OK: EXIF/GPS/comment stripped from JPEG, Orientation kept, text/time from PNG, pixels preserved")
    return 0


def report_to_email(message: str):
    import webbrowser
    from urllib.parse import quote

    subject = "[TOOL-REPORT] photo-metaclean bug or issue"
    webbrowser.open(f"mailto:danyblitz@googlemail.com?subject={quote(subject)}&body={quote(message)}")


def format_desc(kind: str, desc) -> str:
    if isinstance(desc, dict):
        return ", ".join(f"{k}={v}" for k, v in desc.items())
    return str(desc)


def main():
    parser = argparse.ArgumentParser(
        prog="photo-metaclean",
        description="Remove sensitive metadata (EXIF, GPS, comments) from JPEG/PNG images. Audit or clean in place.",
    )
    parser.add_argument("file", nargs="*", help="Image file(s) to audit or clean")
    parser.add_argument("--self-check", action="store_true", help="Run internal correctness check")
    output_mode = parser.add_mutually_exclusive_group()
    output_mode.add_argument("--clean", action="store_true", help="Write a cleaned copy as <name>_clean.<ext>")
    output_mode.add_argument("--in-place", action="store_true", help="Overwrite the original after cleaning")
    parser.add_argument("--verbose", action="store_true", help="Show metadata details before cleaning")
    parser.add_argument("--report", action="store_true", help="Open a pre-filled email to report an issue")
    args = parser.parse_args()

    if args.self_check:
        sys.exit(self_check())

    if not args.file:
        parser.error("at least one image file is required (or use --self-check)")

    summary_lines = []
    for file_arg in args.file:
        p = Path(file_arg)
        if not p.exists():
            print(f"[SKIP] {p}: not found")
            summary_lines.append(f"[SKIP] {p}: not found")
            continue
        suffix = p.suffix.lower()
        if suffix not in (".jpg", ".jpeg", ".png"):
            print(f"[SKIP] {p}: not a JPEG/PNG image")
            summary_lines.append(f"[SKIP] {p}: not a JPEG/PNG image")
            continue

        try:
            info = audit(p)
        except ValueError as e:
            print(f"[SKIP] {p}: {e}")
            summary_lines.append(f"[SKIP] {p}: {e}")
            continue

        print(f"\n=== {p.name} ===")
        print(f"  Format: {info['format']}  |  Size: {fmt(p.stat().st_size)}")
        summary_lines.append(f"=== {p.name} === Format: {info['format']} Size: {fmt(p.stat().st_size)}")

        if not info["has_metadata"]:
            print("  Metadata: none found", "  (already clean)" if args.clean else "")
            if args.clean and not args.in_place:
                out = p.with_name(p.stem + "_clean" + p.suffix)
                out.write_bytes(p.read_bytes())
                print(f"  Cleaned copy written to {out.name} (no metadata to remove, size unchanged)")
            continue

        if args.verbose:
            print("  Metadata found:")
            for kind, desc in info["metadata"]:
                print(f"    {kind}: {format_desc(kind, desc)}")
                summary_lines.append(f"    {kind}: {format_desc(kind, desc)}")

        if args.clean or args.in_place:
            out_path = p if args.in_place else p.with_name(p.stem + "_clean" + p.suffix)
            res = clean(p, out_path)
            print(f"  Cleaned -> {out_path.name} ({fmt(res['output_bytes'])}, {fmt(res['saved_bytes'])} saved)")
        else:
            fields = ", ".join(k for k, _ in info["metadata"]) or "(none printable)"
            print(f"  Metadata present: {fields}")
            print("  Use --clean to write a sanitized copy, or --in-place to overwrite.")

    if args.report:
        report_to_email("\n".join(summary_lines))
        print("\n  Email draft opened — send it and I'll get notified automatically.")


if __name__ == "__main__":
    main()