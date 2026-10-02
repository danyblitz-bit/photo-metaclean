# Photo MetaClean

Remove sensitive metadata from JPEG and PNG images before you share them. One command, three modes.

## Why

Every photo taken with a smartphone quietly carries **GPS coordinates, camera model, software and exact timestamps** in EXIF. When you email it, upload it to a client portal, or post it publicly, that data travels with the file — a geotag can reveal your home, your office, or a private shoot location. Photo MetaClean strips it at the byte level: no re-encode, no quality loss, no cloud upload.

## Install & Run

Zero dependencies — Python standard library only.

```bash
# Inspect what's hidden in an image
python -m tools.photo-metaclean photo.jpg

# See the full metadata list (GPS, camera, timestamps)
python -m tools.photo-metaclean photo.jpg --verbose

# Write a sanitized copy
python -m tools.photo-metaclean photo.jpg --clean
# -> photo_clean.jpg

# Overwrite the original
python -m tools.photo-metaclean photo.jpg --in-place

# Verify the tool works on your machine
python -m tools.photo-metaclean --self-check
```

Works with multiple files at once: `python -m tools.photo-metaclean *.jpg --clean`.

## Options

| Flag | Description |
|------|-------------|
| `--clean` | Write cleaned copy as `<name>_clean.<ext>` |
| `--in-place` | Overwrite the original file after cleaning |
| `--verbose` | List all metadata found before cleaning |
| `--self-check` | Run a built-in correctness test |

## Why the byte-level strip

Most editors "remove metadata" by re-encoding the image — losing quality and, in some cases, leaving thumbnail or maker-note residue. Photo MetaClean rewrites the JPEG/PNG container and **drops the metadata segments themselves**:

- **JPEG**: APP1 (EXIF and XMP), APP13 (IPTC/Photoshop) and COM comments. JFIF, ICC color profile and Adobe APP14 are preserved. Pixel data (SOF/SOS/entropy) is copied byte-for-byte.
- **PNG**: `tEXt`, `zTXt`, `iTXt`, `tIME` and `eXIf` chunks removed. Image data (`IDAT`) untouched.

No re-encode — an 8 MB photo stays an 8 MB photo, only lighter in data.

## Support the Project

Photo MetaClean is free and open source. Like it?

- [Get the DevTools Bundle](https://danyblitz.gumroad.com/l/zjkam) — 3 other tools + guide, pay what you want. Binaries are free here too; the bundle is support
- [Buy me a coffee](https://danyblitz.gumroad.com/l/hrvpiu) — one-time support

## Report a bug

Found a bug or something weird? Run:

```bash
python -m tools.photo-metaclean --report
```

This opens a pre-filled email. Send it and I'll get notified automatically.

You can also email **danyblitz@googlemail.com** directly. Use the subject format:

```
[TOOL-REPORT] photo-metaclean <what happened>
```

Attach the image or log output if you have one.

## License

MIT