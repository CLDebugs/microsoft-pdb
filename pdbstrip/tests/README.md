# Smoke test

Build a full MSVC PDB, strip it, and confirm both PDBs can be read:

```bat
call "%VSINSTALLDIR%\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /Zi /Od /EHsc fixture.cpp /link /DEBUG:FULL /PDB:fixture.pdb
..\pdbstrip.exe fixture.pdb fixture-stripped.pdb
```

The stripped PDB retains `private_helper` and `private_local`, but debugger
source lookup and file/line enumeration return no results.

`verify.cpp` performs that check through Microsoft DIA. Pass the stripped PDB
and the full path to the installed `msdia140.dll`.

The smoke test should also confirm that the output is smaller and that the
fixture source path and `fixture.cpp` do not occur in the stripped file's raw
bytes.
