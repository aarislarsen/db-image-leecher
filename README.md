# db-image-leecher

Scan a **SQLite database** for files hiding in `BLOB`/`TEXT` columns, inspect
them, and pull them back out. Built for digital-forensics / OSINT triage of
app databases (messengers, note apps, caches) that stash attachments inline.

For every value stored in the database it will:

- **Identify files** by magic bytes — images, audio, documents, archives, etc.
- **Read EXIF** from images: date taken, GPS location (as decimal lat/lon),
  camera make/model, plus a full tag dump.
- **Read document properties** from Office/OpenDocument files: author, last
  editor, created/modified dates, application, company, revision…
- **Decode base64** payloads and inspect what's inside them.
- **Carve** files embedded part-way into a blob (e.g. a PNG glued onto a header).
- **Extract strings** — readable ASCII runs inside otherwise-binary blobs.
- **Extract** any selection of the above to disk.

## Install

Requires Python 3.8+.

```bash
pip install Pillow piexif olefile
```

| Package  | Used for                                             | Required?            |
|----------|------------------------------------------------------|----------------------|
| `Pillow` | EXIF parsing                                         | **yes**              |
| `piexif` | only by the test examples below (writing EXIF)       | optional             |
| `olefile`| reading properties from legacy `.doc/.xls/.ppt`      | optional (falls back gracefully) |

Then drop `db_image_leecher.py` anywhere on your path, or run it in place.

## Usage

```bash
python3 db_image_leecher.py <path-to-db-file> [options]
```

Example:

```bash
python3 db_image_leecher.py messages.db
```

```
Scanning messages.db ...

Found 4 embedded file(s):

#  TYPE   SIZE  LOCATION        DATE                 GPS                    CAMERA                FINDINGS
-  ----  -----  --------------  -------------------  ---------------------  --------------------  ------------------
0  jpg   1.1KB  media.data#1    2022:08:11 18:45:00  40.748333, -73.985833  NIKON CORP NIKON D750  13 str
1  docx  1.4KB  files.blob#7    -                    -                      -                     author=John Smith
2  mp3    66B   media.data#4    -                    -                      -                     1 str
3  bin   123B   cache.payload#3 -                    -                      -                     2 embed[zip@8, png@47]

Commands:
  <sel>        extract (e.g. "all", "0,2,5", "0-4,9")
  s <sel>      show full detail (EXIF, doc properties, embeds, strings)
  Enter        quit
> s 0
```

### Interactive commands

Shown after the table when run in a terminal:

| Input        | Action                                                           |
|--------------|------------------------------------------------------------------|
| `all`, `0,2,5`, `0-4,9` | extract those rows to the output directory            |
| `s <sel>`    | print full detail (EXIF dump, document properties, base64 info, carved embeds, strings) for the selection — does **not** extract |
| `d <sel>`    | alias for `s`                                                    |
| *(empty)*    | quit                                                             |

Selections accept `all`, comma lists, and `a-b` ranges in any mix.

### Options

| Option            | Description                                                           |
|-------------------|-----------------------------------------------------------------------|
| `--out DIR`       | output directory for extracted files (default: `./extracted`)         |
| `--images-only`   | list only image files                                                 |
| `--files-only`    | list only recognized files/images/audio (hide bare binary/strings blobs) |
| `--min-strings N` | min readable-string runs before a raw binary blob is flagged (default: `3`) |
| `--details`       | after the table, print full detail for **every** listed blob (works when piped) |
| `--json PATH`     | write results as JSON to `PATH` (`-` for stdout)                      |
| `-h` / `--help` / `-help` | show help                                                     |

## Output columns

| Column     | Meaning                                                          |
|------------|------------------------------------------------------------------|
| `#`        | selection index                                                  |
| `TYPE`     | detected extension (`jpg`, `docx`, `mp3`, `bin`, …)              |
| `SIZE`     | blob size                                                        |
| `LOCATION` | `table.column#rowid` where the blob lives                        |
| `DATE`     | EXIF date taken (images only)                                    |
| `GPS`      | decimal `lat, lon` from EXIF (images only)                       |
| `CAMERA`   | EXIF make + model (images only)                                  |
| `FINDINGS` | document author, base64 target, carved embeds, string count      |

On a color terminal, types are color-coded (images green, audio magenta,
documents blue, …) and GPS is highlighted. Color is disabled automatically
when piped.

## JSON output

`--json` emits a list of records (no raw bytes), e.g.:

```json
{
  "index": 0,
  "kind": "image",
  "ext": "jpg",
  "size_bytes": 1144,
  "table": "media",
  "column": "data",
  "rowid": 1,
  "exif": {
    "date": "2022:08:11 18:45:00",
    "latitude": 40.748333,
    "longitude": -73.985833,
    "camera": "NIKON CORPORATION NIKON D750",
    "width": 100,
    "height": 80,
    "all_tags": { "Make": "NIKON CORPORATION", "LensModel": "24-70mm f/2.8", "...": "..." }
  },
  "analysis": {
    "office": null,
    "base64": null,
    "binary": true,
    "embedded_files": [],
    "string_count": 13,
    "strings_sample": ["NIKON CORPORATION", "24-70mm f/2.8", "..."]
  }
}
```

## What gets detected

- **Images:** jpg, png, gif, bmp, tiff, webp, heic
- **Audio:** mp3, flac, wav, aac, m4a, ogg
- **Documents:** docx/xlsx/pptx (OOXML), odt/ods/odp (OpenDocument),
  legacy doc/xls/ppt (OLE compound files)
- **Other files:** pdf, zip, gz, 7z, rar, mp4, sqlite
- **base64 text** that decodes to any of the above
- **Carved embeds:** png/jpg/gif/pdf/zip/7z/rar/gz/ogg/flac/mp3 signatures
  found *inside* a larger blob
- **Binary with readable strings:** blobs that aren't a known type but contain
  several printable string runs

## How it works

The database is opened **read-only**. Every row of every table is scanned; any
`BLOB`/`TEXT` value is classified by its leading magic bytes (with base64 and
Office/ODF handled specially). Images are routed through Pillow for EXIF,
documents through `zipfile`+XML (or `olefile`) for properties. Nothing is
written to the source database.

Extracted files are named `table_column_rowid.ext` in the output directory.
base64-wrapped payloads are decoded on extraction; carved embeds are written
best-effort as `..._embedN_<offset>.ext`.

## Limitations

- Blobs are held in memory during the scan — heavy on very large databases.
- Carved embeds are sliced from their offset to the end of the blob (no true
  length parsing), so they may carry trailing bytes.
- base64 detection only fires on a value that is *entirely* base64, not a
  base64 substring inside other text.
- GPS is reported as raw decimal coordinates; there is no reverse-geocoding
  (no network calls are made).
- Legacy OLE property parsing needs `olefile`; without it those documents are
  still detected but properties are skipped.

## Legal / ethics

Intended for authorized forensic analysis, incident response, security
research, and inspecting your own data. Only run it against databases you have
permission to examine.

## License

[MIT](LICENSE)
