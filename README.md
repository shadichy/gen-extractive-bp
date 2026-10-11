# gen-extractive-bp

Scan a staged payload directory (`$pkgdirprefix` layout: `lib64/`, `lib/`,
`bin/`, `share/`, `include/`, `etc/`, `*.apk`) and generate an extractive
APEX `Android.bp` (Soong) so prebuilt payloads can be shoved back into an
Android tree.

## Usage

```sh
python3 gen_extractive_bp.py PAYLOAD_DIR [-o Android.bp] [options]
```

Useful flags: `--name`, `--upstream`, `--apex-pkg`, `--prefix` (e.g. `ext-`
for tree collisions), `--arch` (default `x86_64`), `--flat-srcs`,
`--certificate` (default: `presigned`), `-host` / `--host` (host-only
package: forces `host_supported` + `device_supported: false` on code
modules), `--no-availability`,
`--no-prefer`, `--no-check-elf`, `--no-apex-available`, `--no-etc`.

## Mapping

| Payload file | Soong module |
|---|---|
| `lib64/*.so`, `lib/*.so` (+ versioned `.so.*`, collapsed per symlink chain) | `cc_prebuilt_library_shared` (arch-map `srcs`) |
| `*.a` | `cc_prebuilt_library_static` |
| `*.jar` | `java_import` (`host_supported`) |
| `*.apk` | `android_app_import` (`presigned`) |
| ELF executables | `cc_prebuilt_binary` |
| shell scripts (shebang + exec bit) | `sh_binary` |
| `*.h`/`*.hpp` (grouped by dir) | `cc_library_headers <group>_headers` |
| `etc/**` | `prebuilt_etc` (per file) |
| `*.apex` | `prebuilt_apex` (full ext form; `.dev`/`.doc` sniffed non-installable) |

Everything else is skipped with a warning. A `NOTICE` file at the payload
root produces a `license` stanza (as in `system/core`); otherwise the
`package` stanza defaults to `Android-Apache-2.0`.

## Conventions

Output follows the extractive-APEX blueprint style used across the
BlissLabs prebuilt fleet (`apex/apache-xml`, `apex/core`, `apex/expat`,
`apex/dmidecode`): `prefer: true`, `vendor/product/recovery_available` +
`host_supported` on cc modules, `check_elf_files: false`, arch-map `srcs`,
per-group `<lib>_headers` with `apex_available`, upstream-soname module
names (the `ext` prefix lives on the APEX *package*, not on bp modules).

Deterministic output (byte-identical reruns); parses clean under `bp2ninja`.

## Caveats

**Review before use.** `.so` chains collapse to one module named after the
shortest link with `srcs` on the real file; adjust `DT_SONAME` needs by
hand. Name collisions get `_2`-style suffixes — rename deliberately.
