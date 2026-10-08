#!/usr/bin/env python3
"""db-image-leecher: scan a SQLite DB for embedded image files, read EXIF
(date taken, GPS location, camera), and extract selected images to disk.

Usage:
    python3 db_image_leecher.py <path-to-db-file> [--out DIR] [--json PATH]
"""

import argparse
import base64
import binascii
import io
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
import zipfile

try:
    from PIL import Image, ExifTags
except ImportError:
    sys.exit("Pillow required: pip install Pillow")


# --- file-type detection by magic bytes ----------------------------------

# (extension, matcher) — matcher(blob) -> bool
def _match(sig, off=0):
    return lambda b: b[off:off + len(sig)] == sig


IMAGE_SIGS = [
    ("jpg", _match(b"\xff\xd8\xff")),
    ("png", _match(b"\x89PNG\r\n\x1a\n")),
    ("gif", _match(b"GIF87a")),
    ("gif", _match(b"GIF89a")),
    ("bmp", _match(b"BM")),
    ("tif", _match(b"II*\x00")),           # little-endian TIFF
    ("tif", _match(b"MM\x00*")),           # big-endian TIFF
    ("webp", lambda b: b[0:4] == b"RIFF" and b[8:12] == b"WEBP"),
    ("heic", lambda b: b[4:8] == b"ftyp" and b[8:12] in (
        b"heic", b"heix", b"hevc", b"mif1", b"heis", b"hevm")),
]

AUDIO_SIGS = [
    ("mp3", _match(b"ID3")),                        # ID3v2-tagged mp3
    ("mp3", lambda b: b[0] == 0xFF and (b[1] & 0xE0) == 0xE0),  # MPEG sync
    ("flac", _match(b"fLaC")),
    ("wav", lambda b: b[0:4] == b"RIFF" and b[8:12] == b"WAVE"),
    ("aac", lambda b: b[0] == 0xFF and (b[1] & 0xF6) == 0xF0),  # ADTS
    ("m4a", lambda b: b[4:8] == b"ftyp" and b[8:11] == b"M4A"),
    ("ogg", _match(b"OggS")),                       # ogg (vorbis/opus/flac)
]

# non-image/audio file types we still report as "files" (no EXIF attempted)
OTHER_SIGS = [
    ("pdf", _match(b"%PDF-")),
    ("zip", _match(b"PK\x03\x04")),
    ("gz", _match(b"\x1f\x8b")),
    ("7z", _match(b"7z\xbc\xaf\x27\x1c")),
    ("rar", _match(b"Rar!\x1a\x07")),
    ("mp4", lambda b: b[4:8] == b"ftyp"),
    ("sqlite", _match(b"SQLite format 3\x00")),
]

# Distinctive (>=4 byte) literal signatures used for *carving*: finding a
# file embedded anywhere inside a blob, not just at offset 0.
CARVE_MAGIC = [
    ("image", "png",  b"\x89PNG\r\n\x1a\n"),
    ("image", "jpg",  b"\xff\xd8\xff"),
    ("image", "gif",  b"GIF87a"),
    ("image", "gif",  b"GIF89a"),
    ("file",  "pdf",  b"%PDF-"),
    ("file",  "zip",  b"PK\x03\x04"),
    ("file",  "7z",   b"7z\xbc\xaf\x27\x1c"),
    ("file",  "rar",  b"Rar!\x1a\x07"),
    ("file",  "gz",   b"\x1f\x8b\x08"),
    ("audio", "ogg",  b"OggS"),
    ("audio", "flac", b"fLaC"),
    ("audio", "mp3",  b"ID3"),
]


def sniff(blob):
    """Return (kind, ext) where kind is 'image'|'audio'|'file'|None,
    testing signatures at offset 0 only."""
    if not blob or len(blob) < 8:
        return None, None
    for ext, fn in IMAGE_SIGS:
        if fn(blob):
            return "image", ext
    for ext, fn in AUDIO_SIGS:
        if fn(blob):
            return "audio", ext
    for ext, fn in OTHER_SIGS:
        if fn(blob):
            return "file", ext
    return None, None


# --- EXIF parsing ----------------------------------------------------------

_TAGS = {v: k for k, v in ExifTags.TAGS.items()}
_GPS = {v: k for k, v in ExifTags.GPSTAGS.items()}


def _ratio(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        try:
            return x[0] / x[1]
        except Exception:
            return None


def _dms_to_deg(dms, ref):
    try:
        d = _ratio(dms[0]); m = _ratio(dms[1]); s = _ratio(dms[2])
        if None in (d, m, s):
            return None
        deg = d + m / 60.0 + s / 3600.0
        # ref may arrive as str, bytes, or carry a trailing NUL — normalize
        # before the sign test so S/W hemispheres are never missed.
        if isinstance(ref, bytes):
            ref = ref.decode("ascii", "replace")
        if str(ref).strip().strip("\x00").upper()[:1] in ("S", "W"):
            deg = -deg
        return round(deg, 6)
    except Exception:
        return None


def _exif_val(v):
    """Human-readable form of a raw EXIF value."""
    if isinstance(v, bytes):
        return v.decode("ascii", "replace").rstrip("\x00").strip()
    if isinstance(v, str):
        return v.rstrip("\x00").strip()
    # Pillow IFDRational and tuples thereof
    try:
        from PIL.TiffImagePlugin import IFDRational
        if isinstance(v, IFDRational):
            return str(float(v)) if v._denominator else str(v)
    except Exception:
        pass
    if isinstance(v, (tuple, list)):
        return ", ".join(_exif_val(x) for x in v)
    return str(v)


def _dump_ifd(exif, ifd_enum, name_map, prefix=""):
    """Return {tagname: readable} for one IFD."""
    out = {}
    try:
        d = exif.get_ifd(ifd_enum)
    except Exception:
        return out
    for k, v in d.items():
        name = name_map.get(k, f"0x{k:04x}")
        out[prefix + name] = _exif_val(v)
    return out


def read_exif(blob):
    """Return dict with date/camera/gps + full tag dump, or None."""
    try:
        img = Image.open(io.BytesIO(blob))
        exif = img.getexif()
    except Exception:
        return None
    if not exif:
        return None

    def tag(name):
        return exif.get(_TAGS.get(name, -1))

    # camera
    make = tag("Make")
    model = tag("Model")
    camera = " ".join(str(x).strip() for x in (make, model) if x) or None

    # date — prefer DateTimeOriginal (in Exif IFD), fall back to DateTime
    date = None
    try:
        sub = exif.get_ifd(ExifTags.IFD.Exif)
        date = sub.get(_TAGS.get("DateTimeOriginal")) \
            or sub.get(_TAGS.get("DateTimeDigitized"))
    except Exception:
        pass
    date = date or tag("DateTime")

    # gps
    lat = lon = None
    try:
        gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
        if gps:
            lat = _dms_to_deg(gps.get(_GPS["GPSLatitude"]),
                              gps.get(_GPS["GPSLatitudeRef"]))
            lon = _dms_to_deg(gps.get(_GPS["GPSLongitude"]),
                              gps.get(_GPS["GPSLongitudeRef"]))
    except Exception:
        pass

    # full tag dump: base IFD0 + Exif sub-IFD + GPS sub-IFD
    allt = {}
    for k, v in exif.items():
        allt[ExifTags.TAGS.get(k, f"0x{k:04x}")] = _exif_val(v)
    allt.update(_dump_ifd(exif, ExifTags.IFD.Exif, ExifTags.TAGS))
    allt.update(_dump_ifd(exif, ExifTags.IFD.GPSInfo, ExifTags.GPSTAGS,
                          prefix="GPS."))

    if not any((camera, date, lat is not None)) and not allt:
        return None
    return {"camera": camera, "date": date,
            "lat": lat, "lon": lon,
            "w": img.width, "h": img.height, "all": allt}


# --- deep blob analysis ----------------------------------------------------

_B64_RE = re.compile(rb"^[A-Za-z0-9+/\s]+={0,2}\s*$")
_PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t"


def try_base64(blob):
    """If the whole value is base64 text, decode it and sniff the result.
    Returns {'data','kind','ext'} or None."""
    s = blob.strip()
    if len(s) < 24 or not _B64_RE.match(s):
        return None
    compact = re.sub(rb"\s", b"", s)
    if len(compact) % 4 != 0:
        return None
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(data) < 8:
        return None
    kind, ext = sniff(data)
    return {"data": data, "kind": kind, "ext": ext or "bin"}


def carve(blob, limit=12):
    """Find file signatures embedded past offset 0. Returns list of
    {'offset','kind','ext'}. A signature at offset 0 is the blob's own
    primary type, not an embed, so it is skipped."""
    hits = []
    for kind, ext, sig in CARVE_MAGIC:
        start = 1  # offset 0 == primary, never an embed
        while len(hits) < limit:
            i = blob.find(sig, start)
            if i < 0:
                break
            hits.append({"offset": i, "kind": kind, "ext": ext})
            start = i + 1
    hits.sort(key=lambda h: h["offset"])
    return hits[:limit]


# --- Office / OpenDocument metadata ---------------------------------------

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _xml_props(data):
    """Collect {localname: text} for leaf elements with text content."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return {}
    out = {}
    for el in root.iter():
        if len(el) == 0 and el.text and el.text.strip():
            key = el.tag.rsplit("}", 1)[-1]   # strip XML namespace
            out.setdefault(key, el.text.strip())
    return out


def _ole_office(blob):
    """Parse metadata from a legacy OLE compound file (.doc/.xls/.ppt)."""
    res = {"format": "ole", "ext": "ole", "props": {}}
    try:
        import olefile
    except ImportError:
        res["props"]["_note"] = ("legacy OLE compound file; "
                                 "`pip install olefile` to read properties")
        return res
    try:
        ole = olefile.OleFileIO(io.BytesIO(blob))
        md = ole.get_metadata()
        for attr in ("author", "last_saved_by", "title", "subject",
                     "keywords", "comments", "template", "revision_number",
                     "create_time", "last_saved_time", "num_pages",
                     "num_words", "creating_application", "company"):
            v = getattr(md, attr, None)
            if v not in (None, b"", ""):
                res["props"][attr] = _exif_val(v)
        streams = {"/".join(s) for s in ole.listdir()}
        if any("WordDocument" in s for s in streams):
            res["ext"] = "doc"
        elif any("Workbook" in s or s == "Book" for s in streams):
            res["ext"] = "xls"
        elif any("PowerPoint" in s for s in streams):
            res["ext"] = "ppt"
        ole.close()
    except Exception as e:
        res["props"]["_note"] = f"OLE parse failed: {e}"
    return res


def detect_office(blob):
    """Return {'format','ext','props'} if blob is an Office/ODF document,
    else None. Handles OOXML (docx/xlsx/pptx), ODF, and legacy OLE."""
    if blob[:8] == _OLE_MAGIC:
        return _ole_office(blob)
    if blob[:4] != b"PK\x03\x04":
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
        names = set(zf.namelist())
    except Exception:
        return None

    # OOXML (Microsoft Office 2007+)
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            ext = "docx"
        elif any(n.startswith("xl/") for n in names):
            ext = "xlsx"
        elif any(n.startswith("ppt/") for n in names):
            ext = "pptx"
        elif not any(n.startswith("docProps/") for n in names):
            return None          # some other OPC zip, not an office doc
        else:
            ext = "ooxml"
        props = {}
        for fn in ("docProps/core.xml", "docProps/app.xml"):
            if fn in names:
                try:
                    props.update(_xml_props(zf.read(fn)))
                except Exception:
                    pass
        return {"format": "ooxml", "ext": ext, "props": props}

    # OpenDocument (LibreOffice / OpenOffice)
    if "mimetype" in names:
        try:
            mt = zf.read("mimetype").decode("ascii", "replace")
        except Exception:
            mt = ""
        if mt.startswith("application/vnd.oasis.opendocument"):
            ext = {"text": "odt", "spreadsheet": "ods",
                   "presentation": "odp", "graphics": "odg"}.get(
                       mt.rsplit(".", 1)[-1], "odf")
            props = _xml_props(zf.read("meta.xml")) \
                if "meta.xml" in names else {}
            return {"format": "odf", "ext": ext, "props": props}
    return None


def is_valid_zip(blob):
    try:
        zipfile.ZipFile(io.BytesIO(blob)).close()
        return True
    except Exception:
        return False


def is_binary(blob):
    """True if blob looks like raw binary rather than plain text."""
    if b"\x00" in blob[:4096]:
        return True
    sample = blob[:4096]
    if not sample:
        return False
    nonprint = sum(1 for c in sample if c not in _PRINTABLE)
    return nonprint / len(sample) > 0.30


def extract_strings(blob, minlen=5, limit=25):
    """Readable ASCII runs. Returns (sample_list, total_count)."""
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % minlen, blob)
    decoded = [r.decode("ascii", "replace") for r in runs]
    return decoded[:limit], len(decoded)


def analyze(blob, primary_kind=None, min_strings=3):
    """Deep-inspect one blob. Returns an analysis dict."""
    a = {"base64": None, "embeds": [], "strings": [], "n_strings": 0,
         "binary": is_binary(blob), "office": None}

    b64 = try_base64(blob)
    if b64:
        a["base64"] = b64

    # carve embedded files; skip for images (they always carry thumbnails /
    # marker bytes that look like embeds) and for real archives (zip members).
    if primary_kind != "image" and not is_valid_zip(blob):
        a["embeds"] = carve(blob)

    sample, total = extract_strings(blob)
    a["strings"], a["n_strings"] = sample, total
    return a


def classify(blob, min_strings=3):
    """Top-level decision for one bytes value: (kind, ext, analysis) or
    (None, None, None) if nothing interesting."""
    kind, ext = sniff(blob)
    a = analyze(blob, kind, min_strings)

    # Office/ODF document? (primary blob, or a base64-wrapped one)
    office = detect_office(blob)
    if not office and a["base64"]:
        office = detect_office(a["base64"]["data"])
    if office:
        a["office"] = office
        return "office", office["ext"], a

    if kind is None:
        if a["base64"]:
            kind = "base64"
            ext = a["base64"]["ext"]
        elif a["embeds"]:
            kind, ext = "container", "bin"
        elif a["binary"] and a["n_strings"] >= min_strings:
            kind, ext = "binary", "bin"
        else:
            return None, None, None
    return kind, ext, a


# --- DB scanning -----------------------------------------------------------

def scan_db(path, min_strings=3):
    """Return candidate dicts for every bytes value that is a file,
    base64-wrapped payload, container, or binary with readable strings."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.text_factory = bytes  # keep raw bytes; don't choke on non-UTF8
    cur = con.cursor()

    tables = [r[0].decode() for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

    found = []
    for t in tables:
        try:
            info = con.execute(f'PRAGMA table_info("{t}")').fetchall()
        except sqlite3.Error:
            continue
        cols = [c[1].decode() for c in info]
        # does this table have a usable rowid?
        has_rowid = True
        try:
            con.execute(f'SELECT rowid FROM "{t}" LIMIT 1')
        except sqlite3.Error:
            has_rowid = False
        sel = ("rowid, " if has_rowid else "") + ", ".join(
            f'"{c}"' for c in cols)
        try:
            rows = con.execute(f'SELECT {sel} FROM "{t}"')
        except sqlite3.Error:
            continue
        for row in rows:
            rid = row[0] if has_rowid else None
            vals = row[1:] if has_rowid else row
            for col, val in zip(cols, vals):
                if not isinstance(val, (bytes, bytearray)):
                    continue
                blob = bytes(val)
                kind, ext, a = classify(blob, min_strings)
                if kind is None:
                    continue
                rec = {"table": t, "column": col, "rowid": rid,
                       "ext": ext, "kind": kind, "size": len(blob),
                       "blob": blob, "analysis": a, "exif": None}
                # parse EXIF on the real image bytes (base64 may wrap one)
                img_bytes = a["base64"]["data"] if (
                    a["base64"] and a["base64"]["kind"] == "image") else (
                    blob if kind == "image" else None)
                if img_bytes:
                    rec["exif"] = read_exif(img_bytes)
                found.append(rec)
    con.close()
    return found


# --- presentation / extraction --------------------------------------------

def _s(x):
    return x.decode(errors="replace") if isinstance(x, bytes) else str(x)


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024


def _cell(r, field):
    """One display string for a given column of record r."""
    e = r["exif"]
    if field == "idx":
        return str(r["_i"])
    if field == "type":
        return r["ext"]
    if field == "size":
        return _human(r["size"])
    if field == "location":
        return f'{r["table"]}.{r["column"]}#{r["rowid"]}'
    if field == "date":
        return _s(e["date"]) if e and e["date"] else "-"
    if field == "gps":
        if e and e["lat"] is not None and e["lon"] is not None:
            return f'{e["lat"]}, {e["lon"]}'
        return "-"
    if field == "camera":
        return _s(e["camera"]) if e and e["camera"] else "-"
    if field == "findings":
        return findings_str(r.get("analysis"))
    return "-"


def findings_str(a):
    """Short summary of deep-analysis results for the table."""
    if not a:
        return "-"
    parts = []
    off = a.get("office")
    if off:
        p = off["props"]
        who = p.get("creator") or p.get("author") or p.get("initial-creator")
        parts.append("author=" + who if who else off["format"])
    if a.get("base64"):
        parts.append(f'b64→{a["base64"]["ext"]}')
    emb = a.get("embeds") or []
    if emb:
        shown = ", ".join(f'{h["ext"]}@{h["offset"]}' for h in emb[:3])
        more = f' +{len(emb) - 3}' if len(emb) > 3 else ""
        parts.append(f'{len(emb)} embed[{shown}{more}]')
    if a.get("n_strings"):
        parts.append(f'{a["n_strings"]} str')
    return "; ".join(parts) if parts else "-"


# (header, field key, align)  align: '<' left, '>' right
COLUMNS = [
    ("#",        "idx",      ">"),
    ("TYPE",     "type",     "<"),
    ("SIZE",     "size",     ">"),
    ("LOCATION", "location", "<"),
    ("DATE",     "date",     "<"),
    ("GPS",      "gps",      "<"),
    ("CAMERA",   "camera",   "<"),
    ("FINDINGS", "findings", "<"),
]

# ANSI codes. Scanning a long list, the eye wants two things fast:
# is this an image, and does it carry EXIF? So: image type green /
# other files yellow; present EXIF values bright, absent "-" dimmed;
# GPS highlighted (the OSINT-interesting field).
C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "green": "\033[32m", "yellow": "\033[33m", "cyan": "\033[36m",
    "magenta": "\033[35m", "blue": "\033[34m", "bblue": "\033[94m",
}

TYPE_COLOR = {
    "image": C["green"], "audio": C["magenta"], "file": C["yellow"],
    "base64": C["cyan"], "container": C["blue"], "binary": C["dim"],
    "office": C["bblue"],
}


def _color(r, field, val):
    """ANSI code (sans reset) for a cell, or '' for default."""
    if val == "-":
        return C["dim"]
    if field == "type":
        return TYPE_COLOR.get(r["kind"], "")
    if field == "gps":
        return C["cyan"] + C["bold"]
    if field in ("idx", "findings"):
        return C["dim"]
    return ""


def print_table(records, maxw=40):
    use_color = sys.stdout.isatty()
    for i, r in enumerate(records):
        r["_i"] = i
    rows = [[_cell(r, f) for _, f, _ in COLUMNS] for r in records]

    widths = []
    for ci, (head, _, _) in enumerate(COLUMNS):
        w = max([len(head)] + [len(row[ci]) for row in rows])
        widths.append(min(w, maxw))

    def line(cells, rec=None, line_code=None, pad="  "):
        """Render a row. line_code wraps whole line (header/rule);
        otherwise per-cell color is derived from rec via _color()."""
        out = []
        for (head, field, align), val, w in zip(COLUMNS, cells, widths):
            if len(val) > w:
                val = val[:w - 1] + "…"
            padded = f"{val:{align}{w}}"  # pad on PLAIN text (width-safe)
            code = line_code if line_code is not None else (
                _color(rec, field, val) if use_color else "")
            if code:
                padded = code + padded + C["reset"]
            out.append(padded)
        return pad.join(out).rstrip()

    hcode = C["bold"] if use_color else ""
    rcode = C["dim"] if use_color else ""
    print(line([h for h, _, _ in COLUMNS], line_code=hcode))
    print(line(["-" * w for w in widths], line_code=rcode))
    for rec, row in zip(records, rows):
        print(line(row, rec=rec))


def parse_selection(text, n):
    """'all' | '1,3,5' | '1-4,7' -> sorted list of 0-based indices."""
    text = text.strip().lower()
    if text in ("all", "*"):
        return list(range(n))
    out = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return sorted(i for i in out if 0 <= i < n)


def to_json(records):
    """Serializable view of records (no raw blob bytes)."""
    out = []
    for i, r in enumerate(records):
        e = r["exif"]
        a = r.get("analysis") or {}
        b64 = a.get("base64")
        out.append({
            "index": i,
            "kind": r["kind"],
            "ext": r["ext"],
            "size_bytes": r["size"],
            "table": r["table"],
            "column": r["column"],
            "rowid": r["rowid"],
            "exif": None if not e else {
                "date": _s(e["date"]) if e["date"] else None,
                "latitude": e["lat"],
                "longitude": e["lon"],
                "camera": _s(e["camera"]) if e["camera"] else None,
                "width": e["w"],
                "height": e["h"],
                "all_tags": e.get("all", {}),
            },
            "analysis": {
                "office": a.get("office"),
                "base64": None if not b64 else {
                    "decoded_kind": b64["kind"], "decoded_ext": b64["ext"],
                    "decoded_size": len(b64["data"])},
                "binary": a.get("binary"),
                "embedded_files": a.get("embeds", []),
                "string_count": a.get("n_strings", 0),
                "strings_sample": a.get("strings", []),
            },
        })
    return out


def _safe(name):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


def extract(records, idxs, outdir):
    os.makedirs(outdir, exist_ok=True)
    for i in idxs:
        r = records[i]
        a = r.get("analysis") or {}
        stem = f'{r["table"]}_{r["column"]}_{r["rowid"]}'

        # 1) primary payload: base64-decoded bytes if present, else raw blob.
        #    r["ext"] already carries the office subtype (docx/xls/...).
        if a.get("base64"):
            payload, ext = a["base64"]["data"], r["ext"]
        else:
            payload, ext = r["blob"], r["ext"]
        dst = os.path.join(outdir, _safe(f"{stem}.{ext}"))
        with open(dst, "wb") as f:
            f.write(payload)
        print(f'  wrote {dst}  ({len(payload)} bytes)')

        # 2) carved embedded files: best-effort slice from offset -> end
        for n, h in enumerate(a.get("embeds", [])):
            if h["offset"] == 0:
                continue  # that's the primary, already written
            chunk = r["blob"][h["offset"]:]
            cdst = os.path.join(
                outdir, _safe(f'{stem}.embed{n}_{h["offset"]}.{h["ext"]}'))
            with open(cdst, "wb") as f:
                f.write(chunk)
            print(f'  wrote {cdst}  (carved {len(chunk)} bytes, best-effort)')


def print_details(records, idxs, max_strings=0):
    """Print discovered embeds + readable strings for the given records.
    max_strings=0 -> print the full stored sample."""
    use_color = sys.stdout.isatty()
    hdr = (C["bold"], C["dim"], C["cyan"], C["reset"]) if use_color \
        else ("", "", "", "")
    bold, dim, cyan, reset = hdr
    # friendly labels for the most useful document property names
    PROP_LABEL = {
        "creator": "author", "lastModifiedBy": "last modified by",
        "last_saved_by": "last modified by", "created": "created",
        "modified": "modified", "create_time": "created",
        "last_saved_time": "modified", "revision": "revision",
        "revision_number": "revision", "Application": "application",
        "creating_application": "application", "Company": "company",
        "AppVersion": "app version", "initial-creator": "initial author",
        "creation-date": "created", "date": "modified",
        "generator": "application",
    }
    for i in idxs:
        r = records[i]
        a = r.get("analysis") or {}
        loc = f'{r["table"]}.{r["column"]}#{r["rowid"]}'
        print(f'\n{bold}[{i}] {r["kind"]}/{r["ext"]}  {loc}  '
              f'{_human(r["size"])}{reset}')

        office = a.get("office")
        if office:
            print(f'  {cyan}document properties{reset} '
                  f'({office["format"]}):')
            props = office["props"]
            if not props:
                print(f'    {dim}(none found){reset}')
            for k, v in props.items():
                label = PROP_LABEL.get(k, k)
                print(f'    {label:<18} {v}')

        e = r.get("exif")
        if e and e.get("all"):
            print(f'  {cyan}EXIF ({len(e["all"])} tags){reset}:')
            for k, v in e["all"].items():
                vs = v if len(str(v)) <= 80 else str(v)[:79] + "…"
                print(f'    {k:<24} {vs}')

        b64 = a.get("base64")
        if b64:
            print(f'  {cyan}base64{reset} -> {b64["kind"]}/{b64["ext"]} '
                  f'({len(b64["data"])} bytes decoded)')

        emb = a.get("embeds") or []
        if emb:
            print(f'  {cyan}embeds ({len(emb)}){reset}:')
            for h in emb:
                print(f'    offset {h["offset"]:<8} {h["kind"]}/{h["ext"]}')

        strs = a.get("strings") or []
        total = a.get("n_strings", 0)
        if strs:
            shown = strs if max_strings <= 0 else strs[:max_strings]
            cap = "" if len(shown) >= total else \
                f' {dim}(showing {len(shown)} of {total}){reset}'
            print(f'  {cyan}strings ({total}){reset}{cap}:')
            for s in shown:
                print(f'    {dim}|{reset} {s}')
        if not (office or (e and e.get("all")) or b64 or emb or strs):
            print(f'  {dim}(no extra metadata){reset}')


def main():
    ap = argparse.ArgumentParser(
        prog="db_image_leecher.py",
        description="Find files embedded in a SQLite DB and inspect them: "
                    "EXIF (date/GPS/camera), Office/ODF document properties, "
                    "base64 payloads, carved embeds, and readable strings.")
    # argparse gives -h/--help; add -help as an explicit alias too.
    ap.add_argument("-help", action="help", default=argparse.SUPPRESS,
                    help="show this help message and exit")
    ap.add_argument("db", help="path to SQLite .db file")
    ap.add_argument("--out", default="extracted",
                    help="output dir for extracted files (default: ./extracted)")
    ap.add_argument("--images-only", action="store_true",
                    help="list only image files")
    ap.add_argument("--files-only", action="store_true",
                    help="list only recognized files/images/audio "
                         "(hide bare binary/strings-only blobs)")
    ap.add_argument("--min-strings", type=int, default=3, metavar="N",
                    help="min readable-string runs to flag a raw binary "
                         "blob as interesting (default: 3)")
    ap.add_argument("--details", action="store_true",
                    help="after the table, print embeds + readable strings "
                         "for every listed blob")
    ap.add_argument("--json", metavar="PATH",
                    help="write results as JSON to PATH ('-' for stdout)")
    args = ap.parse_args()

    if not os.path.isfile(args.db):
        sys.exit(f"no such file: {args.db}")

    print(f"Scanning {args.db} ...")
    records = scan_db(args.db, min_strings=args.min_strings)
    if args.images_only:
        records = [r for r in records if r["kind"] == "image"]
    elif args.files_only:
        records = [r for r in records
                   if r["kind"] in ("image", "audio", "file")]

    if not records:
        print("No embedded files found.")
        return

    # images-with-EXIF first, then documents/media/files, binary blobs last
    order = {"image": 0, "office": 1, "audio": 2, "file": 3,
             "container": 4, "base64": 5, "binary": 6}
    records.sort(key=lambda r: (order.get(r["kind"], 9), r["exif"] is None))

    print(f"\nFound {len(records)} embedded file(s):\n")
    print_table(records)

    if args.details:
        print_details(records, range(len(records)))

    if args.json:
        data = to_json(records)
        if args.json == "-":
            print("\n" + json.dumps(data, indent=2))
        else:
            with open(args.json, "w") as f:
                json.dump(data, f, indent=2)
            print(f"\nWrote JSON: {args.json}")

    if not sys.stdin.isatty():
        print("\n(non-interactive stdin; skipping selection. "
              "Re-run in a terminal, or use --details / --json with a pipe.)")
        return

    print('\nCommands:\n'
          '  <sel>        extract (e.g. "all", "0,2,5", "0-4,9")\n'
          '  s <sel>      show full detail (EXIF, doc properties, '
          'embeds, strings)\n'
          '  Enter        quit')
    while True:
        try:
            cmd = input("> ").strip()
        except EOFError:
            break
        if not cmd:
            break

        show = False
        if cmd[0] in "sd" and (len(cmd) == 1 or cmd[1] in " \t"):
            show, cmd = True, cmd[1:].strip() or "all"

        try:
            idxs = parse_selection(cmd, len(records))
        except ValueError:
            print("bad selection syntax")
            continue
        if not idxs:
            print("nothing selected")
            continue

        if show:
            print_details(records, idxs)
        else:
            print(f"\nExtracting {len(idxs)} file(s) to {args.out}/")
            extract(records, idxs, args.out)
            print("Done.")
            break


if __name__ == "__main__":
    main()
