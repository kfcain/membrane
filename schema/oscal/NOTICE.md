# OSCAL assessment-results JSON Schema

File: `oscal_assessment-results_schema.json`

Source: NIST OSCAL release v1.1.3, release asset `oscal_assessment-results_schema.json`.

URL: https://github.com/usnistgov/OSCAL/releases/download/v1.1.3/oscal_assessment-results_schema.json

Schema `$id`: `http://csrc.nist.gov/ns/oscal/1.1.3/oscal-ar-schema.json`

SHA-256: `d9e34757f0c12aff61f52b821f0b8f83ba0ba75b3a149a202b08ba82f82bc4c3`

Downloaded: 2026-09-27. The file is byte-for-byte the release asset. Membrane did not change it.

License: the OSCAL project is a work of the United States government. It is in the public domain in the United States and is dedicated to the worldwide public domain under CC0 1.0. Source: National Institute of Standards and Technology. See https://github.com/usnistgov/OSCAL/blob/main/LICENSE.md .

## Version choice

The release v1.1.3 is the newest 1.1.x release. OSCAL v1.2.0 exists. Membrane targets 1.1.3 because the task pins the 1.1.x line. The output document sets `oscal-version` to `1.1.3`.

## Validation note

The schema uses the regular expression classes `\p{L}` and `\p{N}` in the token pattern. The Python `re` module does not support them. `membrane/checks/oscal.py` loads the schema and rewrites these two classes in memory before validation:

- `\p{L}` becomes `[^\W\d_]` (any Unicode letter).
- `\p{N}` becomes `\d` (Unicode decimal digits only; `\p{N}` also covers other numeric characters).

The rewrite is in memory only. The vendored file stays unchanged, and the test suite checks its SHA-256.
