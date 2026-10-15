#!/usr/bin/env python3
"""Generate an extractive APEX payload Android.bp by scanning a staging dir.

Enhanced to:
1. Inspect co-located standard/runtime APEX packages, extract their payloads
   (lib/ and lib64/ shared libraries) to stage alongside dev/static archives.
2. Filter out internal APEX artifacts: _libdummy*, libdummy_*, linker.config.json.
3. Emit prebuilt_apex strictly for runtime APEXes (stripping version numbers,
   ignoring .dev.apex and .doc.apex).
4. Combine matching shared .so and static .a into unified cc_prebuilt_library,
   attaching export_include_dirs automatically.
5. Intelligently discover include directories (at root, src/include, dev-src/include)
   and generate well-known <pkg>_headers and subfolder headers without mangling
   to 'src_headers' or 'dev_src_headers'.
6. Clean Maven coordinates on JAR files to standard AOSP java_import module names.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

HEADER_EXTS = (".h", ".hpp", ".hh", ".hxx", ".h++")
APEX_RE = re.compile(r"\.apex$", re.IGNORECASE)
AVAIL = ["vendor_available", "product_available", "recovery_available", "host_supported"]


def q(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def sanitize(name):
    name = re.sub(r"[.\-]", "_", name)
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    name = name.strip("_") or "unnamed"
    if name[0].isdigit():
        name = "m_" + name
    return re.sub(r"_+", "_", name)


def is_dummy(filename):
    base = os.path.basename(filename)
    return base.startswith("_libdummy") or base.startswith("libdummy_") or base == "_libdummy.so"


def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def is_script(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def elf_arch(path):
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return None
            ei_class = f.read(1)[0]
            f.seek(18)
            e_machine = int.from_bytes(f.read(2), "little")
            if e_machine == 62:
                return "x86_64"
            elif e_machine == 3:
                return "x86"
            elif e_machine == 183:
                return "arm64"
            elif e_machine == 40:
                return "arm"
            elif e_machine == 243:
                return "riscv64"
            return "x86_64" if ei_class == 2 else "x86"
    except (OSError, IndexError):
        return None


def elf_soname(path):
    """Read DT_SONAME from ELF file if readelf is available."""
    try:
        out = subprocess.check_output(["readelf", "-d", path], stderr=subprocess.DEVNULL).decode()
        m = re.search(r"\(SONAME\)\s+Library soname:\s+\[([^\]]+)\]", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def canonical_libname(filename, real_path=None):
    """Derive canonical library name (e.g. libz from libz.so, zlib.so, libz.a)."""
    if real_path and is_elf(real_path):
        sn = elf_soname(real_path)
        if sn:
            sn_clean = re.sub(r"\.so(\..*)?$", "", sn)
            if sn_clean:
                return sn_clean

    base = os.path.basename(filename)
    # Strip extensions
    name = re.sub(r"\.so(\..*)?$", "", base)
    name = re.sub(r"\.a$", "", name)
    # Strip microarch suffixes (-x86_64-v2, -x86_64)
    name = re.sub(r"-x86_64(-v\d+)?$", "", name)
    name = re.sub(r"-arm64(-v\d+)?$", "", name)
    name = re.sub(r"-x86$", "", name)
    name = re.sub(r"-arm$", "", name)
    return name


def clean_jar_name(rel_path):
    """Clean Maven coordinate filename/path to canonical module name."""
    base = os.path.basename(rel_path)
    parts = rel_path.split(os.sep)
    folder = None
    if "share" in parts:
        idx = parts.index("share")
        if len(parts) > idx + 1:
            folder = parts[idx + 1]
    
    # Strip group__
    artifact = re.sub(r"^[a-zA-Z0-9_\.\-]+__", "", base)
    # Strip version suffix
    artifact = re.sub(r"-(\d+(\.\d+)*.*)\.jar$", "", artifact)
    artifact = re.sub(r"\.jar$", "", artifact)
    
    if folder and folder != "share":
        # If folder has distinctive name (e.g. guava-both, guava-jre, guava-android-annotation-stubs)
        if folder.startswith(artifact + "-") or folder != artifact:
            if not (artifact != "guava" and folder == "guava"):
                return folder
    return artifact


def extract_apex_payload(apex_path, dest_dir):
    """Extract apex_payload.img from an APEX zip archive into dest_dir."""
    try:
        with zipfile.ZipFile(apex_path, "r") as z:
            if "apex_payload.img" not in z.namelist():
                return False
            with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as tmp:
                tmp.write(z.read("apex_payload.img"))
                tmp_name = tmp.name
        os.makedirs(dest_dir, exist_ok=True)
        # Try fsck.erofs first
        res = subprocess.run(["fsck.erofs", f"--extract={dest_dir}", tmp_name],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            # Fallback to debugfs
            res = subprocess.run(["debugfs", "-R", f"rdump / {dest_dir}", tmp_name],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        return res.returncode == 0
    except Exception:
        return False


def prop(key, val, indent="    "):
    if isinstance(val, list):
        if not val:
            return None
        lines = ["%s%s: [" % (indent, key)]
        lines += ["%s    %s," % (indent, q(v)) for v in val]
        lines.append("%s]," % indent)
        return "\n".join(lines)
    if isinstance(val, bool):
        return "%s%s: %s," % (indent, key, "true" if val else "false")
    if isinstance(val, str):
        return "%s%s: %s," % (indent, key, q(val))
    return "%s%s: %s," % (indent, key, val)


def emit(modtype, name, props):
    lines = ["%s {" % modtype, "    name: %s," % q(name)]
    for key, val in props:
        rendered = prop(key, val)
        if rendered is not None:
            lines.append(rendered)
    lines.append("}")
    return "\n".join(lines)


def emit_arch_srcs(srcs_by_arch, indent="    "):
    lines = ["%sarch: {" % indent]
    for arch, s in sorted(srcs_by_arch.items()):
        lines.append("%s    %s: {" % (indent, arch))
        lines.append("%s        srcs: [" % indent)
        for path in s:
            lines.append('%s            %s,' % (indent, q(path)))
        lines.append("%s        ]," % indent)
        lines.append("%s    }," % indent)
    lines.append("%s}," % indent)
    return lines


def generate_blueprint(payloaddir, args):
    root = os.path.abspath(payloaddir)
    if not os.path.isdir(root):
        sys.exit("error: not a directory: %s" % payloaddir)

    raw_name = args.name or os.path.basename(root.rstrip("/")) or "payload"
    name = sanitize(raw_name)
    prefix = args.prefix
    avail = [] if args.no_availability else [(k, True) for k in AVAIL]
    check_elf = [] if args.no_check_elf else [("check_elf_files", False)]

    def modname(base):
        return prefix + base

    def with_host(props):
        if not args.host:
            return props
        out = [(k, v) for k, v in props if k not in ("host_supported", "device_supported")]
        out.append(("host_supported", True))
        out.append(("device_supported", False))
        return out

    # ---- 1. Check for co-located standard APEX packages ----
    runtime_apexes = []
    for fn in os.listdir(root):
        if fn.endswith(".apex"):
            stem = re.sub(r"\.apex$", "", fn, flags=re.IGNORECASE)
            clean_apex_name = re.sub(r"-\d+$", "", stem)
            # Skip doc and dev packages for prebuilt_apex
            if re.search(r"\.(dev|doc)$", clean_apex_name, re.IGNORECASE):
                continue
            # Also check if it is extractive APEX (ext- or .ext.)
            is_extractive = bool(re.search(r"(^ext-|\.ext\.)", stem))
            runtime_apexes.append({
                "filename": fn,
                "stem": stem,
                "apex_name": clean_apex_name,
                "is_extractive": is_extractive,
                "full_path": os.path.join(root, fn),
            })

    # Auto-extract runtime APEX payloads if requested or needed
    if not args.no_extract_apex:
        for ap in runtime_apexes:
            # Runtime APEX payload components should be extracted into src/
            ext_dir = os.path.join(root, "src")
            os.makedirs(ext_dir, exist_ok=True)
            # Extract to temp, then merge lib/lib64/bin into ext_dir
            with tempfile.TemporaryDirectory() as tmp_stage:
                if extract_apex_payload(ap["full_path"], tmp_stage):
                    for sub in ["lib", "lib64", "bin"]:
                        src_sub = os.path.join(tmp_stage, sub)
                        if os.path.isdir(src_sub):
                            dest_sub = os.path.join(ext_dir, sub)
                            os.makedirs(dest_sub, exist_ok=True)
                            for item in os.listdir(src_sub):
                                s_item = os.path.join(src_sub, item)
                                d_item = os.path.join(dest_sub, item)
                                if os.path.lexists(d_item):
                                    if os.path.islink(d_item) or os.path.isfile(d_item):
                                        os.unlink(d_item)
                                    elif os.path.isdir(d_item):
                                        shutil.rmtree(d_item)
                                if os.path.islink(s_item):
                                    linkto = os.readlink(s_item)
                                    os.symlink(linkto, d_item)
                                elif os.path.isfile(s_item):
                                    shutil.copy2(s_item, d_item)

    # ---- 2. Walk filesystem and classify files ----
    all_files = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if ".git" in dirnames:
            dirnames.remove(".git")
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if is_dummy(rel):
                continue
            if os.path.islink(full):
                try:
                    target = os.path.realpath(full)
                    if os.path.isfile(target):
                        all_files.append((rel, full, os.path.relpath(target, root), target))
                except OSError:
                    pass
            elif os.path.isfile(full):
                all_files.append((rel, full, None, full))

    # Identify primary include directory
    include_dirs = set()
    header_files = []
    for rel, full, target_rel, real_full in all_files:
        base = os.path.basename(rel)
        if base.endswith(HEADER_EXTS):
            header_files.append((rel, full))
            # Find the "include" directory component
            parts = rel.split(os.sep)
            if "include" in parts:
                idx = parts.index("include")
                inc_dir = os.path.join(*parts[:idx+1])
                include_dirs.add(inc_dir)

    primary_inc_dir = sorted(include_dirs)[0] if include_dirs else None

    # Group libraries by canonical name
    # lib_map[canon_name] = { 'shared': { arch: [rel] }, 'static': { arch: [rel] } }
    lib_map = {}
    jars = []
    apks = []
    binaries = {}
    scripts = []
    etcs = []

    for rel, full, target_rel, real_full in all_files:
        base = os.path.basename(rel)
        if base == "Android.bp" or base == "NOTICE" or base == "SHADOW.txt":
            continue
        if base.endswith(".pkg.tar.zst") or base.endswith(".so.so"):
            continue
        if APEX_RE.search(base):
            continue
        if rel.startswith("etc/") or "/etc/" in rel:
            if base != "linker.config.json" and args.etc:
                etcs.append(rel)
            continue
        if base.endswith(".jar"):
            jars.append(rel)
            continue
        if base.endswith(".apk"):
            apks.append(rel)
            continue
        if base.endswith(HEADER_EXTS):
            continue

        # Shared libraries (.so)
        if re.search(r"\.so(\..*)?$", base):
            arch = elf_arch(real_full) or args.arch
            canon = canonical_libname(rel, real_full)
            if is_dummy(canon):
                continue
            # Prefer canonical names starting with lib
            if not canon.startswith("lib") and ("lib" + canon) in lib_map:
                canon = "lib" + canon
            entry = lib_map.setdefault(canon, {"shared": {}, "static": {}})
            entry["shared"].setdefault(arch, []).append(rel)
            continue

        # Static libraries (.a)
        if base.endswith(".a"):
            arch = args.arch
            canon = canonical_libname(rel, real_full)
            if is_dummy(canon):
                continue
            if not canon.startswith("lib") and ("lib" + canon) in lib_map:
                canon = "lib" + canon
            entry = lib_map.setdefault(canon, {"shared": {}, "static": {}})
            entry["static"].setdefault(arch, []).append(rel)
            continue

        if os.access(real_full, os.X_OK):
            if is_elf(real_full):
                if is_dummy(base):
                    continue
                arch = elf_arch(real_full) or args.arch
                canon_bin = re.sub(r"-x86_64(-v\d+)?$", "", base)
                canon_bin = re.sub(r"-arm64(-v\d+)?$", "", canon_bin)
                canon_bin = re.sub(r"-x86$", "", canon_bin)
                canon_bin = re.sub(r"-arm$", "", canon_bin)
                binaries.setdefault(canon_bin, {}).setdefault(arch, []).append(rel)
                continue
            if is_script(real_full):
                scripts.append(rel)
                continue

    # ---- 3. Emit Stanzas ----
    stanzas = []

    # Header comment & license
    if args.upstream:
        hdr = ("// Auto-generated prebuilt Blueprint for %s\n" % args.upstream)
    else:
        hdr = ("// Auto-generated prebuilt Blueprint for %s\n" % raw_name)
    if args.apex_pkg:
        hdr += ("// Extracted from Extractive APEX package: %s\n" % args.apex_pkg)
    hdr += ("// Generated by tools/gen_extractive_bp.py - REVIEW BEFORE USE\n\n")

    notice = os.path.isfile(os.path.join(root, "NOTICE"))
    if notice:
        lic_name = sanitize(name + "_license")
        hdr += ("package {\n"
                "    default_applicable_licenses: [%s],\n"
                "}\n\n"
                "license {\n"
                "    name: %s,\n"
                "    visibility: [\":__subpackages__\"],\n"
                "    license_kinds: [\n"
                "        \"SPDX-license-identifier-Apache-2.0\",\n"
                "    ],\n"
                "    license_text: [\n"
                "        \"NOTICE\",\n"
                "    ],\n"
                "}\n" % (q(lic_name), q(lic_name)))
    else:
        hdr += ("package {\n"
                "    default_applicable_licenses: [%s],\n"
                "}\n" % q(args.license))

    # prebuilt_apex (strictly for runtime APEXes)
    for ap in runtime_apexes:
        if ap["is_extractive"] and not args.emit_extractive_prebuilt_apex:
            continue
        lines = [
            "prebuilt_apex {",
            "    name: %s," % q(modname(ap["apex_name"])),
            "    apex_name: %s," % q(ap["apex_name"]),
            "    source_apex_name: %s," % q(ap["apex_name"]),
            "    arch: {",
            "        %s: {" % args.arch,
            "            src: %s," % q(ap["filename"]),
            "        },",
            "    },",
            "    filename: %s," % q(ap["filename"]),
        ]
        if not args.no_prefer:
            lines.append("    prefer: true,")
        lines.append("    installable: true,")
        lines.append("}")
        stanzas.append("\n".join(lines))

    # Header modules
    # If subdirectories exist in include_dir, emit header modules for them
    emitted_headers = set()
    if primary_inc_dir:
        abs_inc = os.path.join(root, primary_inc_dir)
        subdirs = [d for d in sorted(os.listdir(abs_inc))
                   if os.path.isdir(os.path.join(abs_inc, d)) and not d.startswith(".")]
        
        # Primary package header module: <pkg>_headers (or lib<pkg>_headers)
        base_pkg = raw_name
        if base_pkg.startswith("lib"):
            main_hdr_name = base_pkg + "_headers"
        else:
            main_hdr_name = "lib" + base_pkg + "_headers"

        h_props = list(avail)
        if not args.no_apex_available:
            h_props.append(("apex_available", ["//apex_available:anyapex", "//apex_available:platform"]))
        h_props.append(("export_include_dirs", [primary_inc_dir]))
        stanzas.append(emit("cc_library_headers", modname(main_hdr_name), with_host(h_props)))
        emitted_headers.add(main_hdr_name)

        for sd in subdirs:
            # Only emit subfolder headers if it matches a library in this package
            # (prevents libchrome from emitting conflicting libbase_headers)
            cand1 = sd if sd.startswith("lib") else "lib" + sd
            cand2 = sd
            if cand1 in lib_map or cand2 in lib_map or base_pkg == "core" or base_pkg == "system_core":
                if sd in ("private", "android"):
                    sub_hdr_name = f"{base_pkg}_{sd}_headers"
                elif not sd.startswith("lib"):
                    sub_hdr_name = f"lib{sd}_headers"
                else:
                    sub_hdr_name = f"{sd}_headers"
                if sub_hdr_name not in emitted_headers:
                    stanzas.append(emit("cc_library_headers", modname(sub_hdr_name), with_host(h_props)))
                    emitted_headers.add(sub_hdr_name)

    # Libraries (cc_prebuilt_library / shared / static)
    for libname, data in sorted(lib_map.items()):
        sh = data["shared"]
        st = data["static"]
        props = with_host(list(avail) + check_elf)
        if primary_inc_dir:
            props.append(("export_include_dirs", [primary_inc_dir]))
        if not args.no_prefer:
            props.append(("prefer", True))
        if not args.no_apex_available:
            props.append(("apex_available", ["//apex_available:anyapex", "//apex_available:platform"]))

        def best_src(arch_map):
            # Choose cleanest source path for given arch
            # Prefer unversioned real path
            out = {}
            for a, paths in arch_map.items():
                p_clean = sorted(paths, key=lambda p: (len(p), p))[0]
                out[a] = [p_clean]
            return out

        if sh and st:
            # UNIFIED cc_prebuilt_library
            lines = ["cc_prebuilt_library {", "    name: %s," % q(modname(libname))]
            for k, v in props:
                rendered = prop(k, v)
                if rendered:
                    lines.append(rendered)
            # shared stanza
            sh_src = best_src(sh)
            lines.append("    shared: {")
            if args.flat_srcs or len(sh_src) == 1 and args.arch in sh_src:
                lines.append("        srcs: [%s]," % q(sh_src[args.arch][0]))
            else:
                lines.extend(emit_arch_srcs(sh_src, indent="        "))
            lines.append("    },")
            # static stanza
            st_src = best_src(st)
            lines.append("    static: {")
            if args.flat_srcs or len(st_src) == 1 and args.arch in st_src:
                lines.append("        srcs: [%s]," % q(st_src[args.arch][0]))
            else:
                lines.extend(emit_arch_srcs(st_src, indent="        "))
            lines.append("    },")
            lines.append("}")
            stanzas.append("\n".join(lines))
        elif sh:
            # Shared only
            lines = ["cc_prebuilt_library_shared {", "    name: %s," % q(modname(libname))]
            for k, v in props:
                rendered = prop(k, v)
                if rendered:
                    lines.append(rendered)
            sh_src = best_src(sh)
            if args.flat_srcs or len(sh_src) == 1 and args.arch in sh_src:
                lines.append("    srcs: [%s]," % q(sh_src[args.arch][0]))
            else:
                lines.extend(emit_arch_srcs(sh_src))
            lines.append("}")
            stanzas.append("\n".join(lines))
        elif st:
            # Static only
            lines = ["cc_prebuilt_library_static {", "    name: %s," % q(modname(libname))]
            for k, v in props:
                rendered = prop(k, v)
                if rendered:
                    lines.append(rendered)
            st_src = best_src(st)
            if args.flat_srcs or len(st_src) == 1 and args.arch in st_src:
                lines.append("    srcs: [%s]," % q(st_src[args.arch][0]))
            else:
                lines.extend(emit_arch_srcs(st_src))
            lines.append("}")
            stanzas.append("\n".join(lines))

    # Java imports (Clean Maven naming)
    used_jar_names = set()
    for rel in sorted(jars):
        clean_name = clean_jar_name(rel)
        mod_name = clean_name
        idx = 2
        while mod_name in used_jar_names:
            mod_name = f"{clean_name}_{idx}"
            idx += 1
        used_jar_names.add(mod_name)
        props = with_host([("jars", [rel]), ("host_supported", True)])
        if not args.no_prefer:
            props.append(("prefer", True))
        stanzas.append(emit("java_import", modname(mod_name), props))

    # APKs
    for rel in sorted(apks):
        base = os.path.basename(rel)
        clean_name = re.sub(r"\.apk$", "", base)
        props = [("apk", rel)]
        if args.certificate:
            props.append(("certificate", args.certificate))
        else:
            props.append(("presigned", True))
        stanzas.append(emit("android_app_import", modname(clean_name), props))

    # Binaries & Scripts
    for base, arch_srcs in sorted(binaries.items()):
        props = with_host(check_elf + ([] if args.no_prefer else [("prefer", True)]))
        lines = ["cc_prebuilt_binary {", "    name: %s," % q(modname(base))]
        for k, v in props:
            rendered = prop(k, v)
            if rendered:
                lines.append(rendered)
        if args.flat_srcs or len(arch_srcs) == 1 and args.arch in arch_srcs:
            lines.append("    srcs: [%s]," % q(arch_srcs[args.arch][0]))
        else:
            lines.extend(emit_arch_srcs(arch_srcs))
        lines.append("}")
        stanzas.append("\n".join(lines))

    for rel in sorted(scripts):
        base = re.sub(r"\.sh$", "", os.path.basename(rel))
        stanzas.append(emit("sh_binary", modname(base), with_host([("src", rel)])))

    # etc
    for rel in sorted(etcs):
        sub = os.path.dirname(os.path.relpath(rel, "etc"))
        props = [("src", rel)]
        if sub and sub != ".":
            props.append(("sub_dir", sub))
        stanzas.append(emit("prebuilt_etc", modname(os.path.basename(rel)), props))

    out = hdr + ("\n" + "\n\n".join(stanzas) + "\n" if stanzas else "\n")
    if not out.endswith("\n"):
        out += "\n"

    if args.output == "-":
        sys.stdout.write(out)
    else:
        with open(args.output, "w") as f:
            f.write(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("payloaddir")
    ap.add_argument("-o", "--output", default="-")
    ap.add_argument("--name", default=None)
    ap.add_argument("--upstream", default=None)
    ap.add_argument("--apex-pkg", default=None)
    ap.add_argument("--prefix", default="")
    ap.add_argument("--license", default="Android-Apache-2.0")
    ap.add_argument("--arch", default="x86_64")
    ap.add_argument("--flat-srcs", action="store_true")
    ap.add_argument("--certificate", default=None)
    ap.add_argument("-host", "--host", dest="host", action="store_true")
    ap.add_argument("--no-availability", action="store_true")
    ap.add_argument("--no-prefer", action="store_true")
    ap.add_argument("--no-check-elf", action="store_true")
    ap.add_argument("--no-apex-available", action="store_true")
    ap.add_argument("--etc", dest="etc", action="store_true", default=True)
    ap.add_argument("--no-etc", dest="etc", action="store_false")
    ap.add_argument("--no-extract-apex", action="store_true",
                    help="do not auto-extract co-located runtime .apex payloads")
    ap.add_argument("--emit-extractive-prebuilt-apex", action="store_true",
                    help="emit prebuilt_apex even for extractive APEXes (ext-*)")
    args = ap.parse_args()

    generate_blueprint(args.payloaddir, args)


if __name__ == "__main__":
    main()
