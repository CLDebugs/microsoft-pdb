# pdbstrip

`pdbstrip.exe` copies an MSVC MSF 7.00 PDB while retaining private symbols,
types, publics, unwind data, and unrelated named streams. It removes:

- legacy C11 line tables
- C13 line, IL-line, file-checksum, and inline-line subsections
- line annotations embedded in `S_INLINESITE` records
- source-file associations on `S_FILESTATIC` records
- DBI source-file and edit-and-continue source metadata
- contents of `srcsrv`, Source Link, and embedded `/src/*` named streams
- source filename bytes referenced from module C13 string tables
- source paths and command arguments referenced by IPI build-info records
- UDT source-line records
- directory components in object names and path-bearing compiler/linker environment records
- matching source names in the global `/names` table

The PDB GUID and age are unchanged, so the output continues to match the
original executable. The input is never modified, and an existing output is
not overwritten. Temporary outputs are created exclusively in the destination
directory and are removed only by the invocation that created them.

## Build

From an x64 Native Tools Command Prompt:

```bat
cl /nologo /std:c++17 /EHsc /W4 /O2 pdbstrip.cpp /Fe:pdbstrip.exe
```

## Usage

```bat
pdbstrip.exe private.pdb private-no-source.pdb
```

During processing, the tool reports each stripping stage, record and stream
counts, explicit no-op decisions when optional source data is absent, and the
final size change.

The tool intentionally supports modern MSF 7.00 PDBs only. Use a full PDB
(`/DEBUG:FULL`), not a partial `/DEBUG:FASTLINK` PDB.

Source-related named-stream entries remain in the PDB name map, but their
streams are zero-filled. The result is then serialized into a compact MSF with
a fresh stream directory and free-page map. The compact output retains the
original PDB GUID and age and remains loadable by Microsoft DIA.
