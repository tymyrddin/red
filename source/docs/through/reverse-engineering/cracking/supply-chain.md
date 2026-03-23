# Supply chain and build artefact analysis

Reverse engineering is not only applied to malware and target applications. Compiled
dependencies, build pipeline outputs, and distributed packages are increasingly part of the
attack surface. The red team angle is identifying what has been tampered with, what slips
through without scrutiny, and where build artefacts diverge from the source they claim to
represent.

## Diffing builds

The most direct approach: compile the same package from source and compare it against the
distributed binary. Differences indicate either that the build environment diverges from what
is documented, or that the distributed binary has been modified after compilation.

`bindiff` (from BinDiff by Google/Zynamics) computes a structural similarity score between
two binaries and shows matched and unmatched functions:

```text
bindiff target.exe reference.exe
```

Functions present in the distributed binary but absent in the locally compiled version are
candidates for review. Functions with identical names but different code are also worth
examining.

For ELF binaries, `radiff2` (from radare2) provides a similar comparison:

```text
radiff2 -A reference.elf distributed.elf
```

`-A` performs analysis on both before diffing, which improves function matching in stripped
binaries.

## Identifying tampered packages

Package managers distribute checksums, but these only verify the package as received from
the distribution channel, not the integrity of the compiled binary relative to the source.

For binaries where source is available, look for:

Unexpected imports: `dumpbin /imports` (Windows) or `rabin2 -i` (Linux) shows all imported
functions. An import that is not referenced in the source code, particularly to networking or
cryptography APIs, is a red flag.

Extra sections: a PE or ELF binary compiled from known source will have a predictable section
layout. An additional section containing executable code that is not part of the compiler
output is suspicious. Check section names and contents against what the compiler toolchain
normally produces.

Timestamp anomalies: the PE header timestamp can be checked against the claimed build date.
Fabricated timestamps are common in tampered binaries, but absent a ground truth, this is
weak evidence on its own.

## Compiled dependency analysis

Third-party dependencies compiled into a final binary are not always visible as separate
files. Statically linked libraries leave traces: symbol names if not stripped, string
constants, algorithm implementations identifiable by their constants.

For a dependency you want to confirm is present and unmodified, extract its characteristic
byte sequences or algorithm constants and search the target binary:

```text
rabin2 -z target.exe | grep -i "OpenSSL"
strings target.exe | grep -i "libcurl"
```

OpenSSL version strings, copyright notices, and error message strings are embedded in
compiled binaries and survive stripping. They identify both the library and the version,
which can be checked against known vulnerability databases.

## Build pipeline targets

The build pipeline itself is an attack surface. Artefacts to examine:

Makefiles and build scripts: arbitrary code execution during the build process. Look for
network calls, downloads from external sources, or post-build steps that modify the output.

CI/CD configuration: actions, workflows, and pipeline definitions can pull from external
repositories or execute scripts. A compromised dependency or a modified workflow step may
modify the binary at build time.

Compiler and linker wrappers: some projects use custom compiler scripts. If the wrapper is
in the dependency chain, it can modify the output. Compare the wrapper's behaviour against
a known-clean version.

The analysis workflow is the same as for any binary: identify what the artefact actually does,
compare against what it is documented to do, and flag divergences for investigation.
