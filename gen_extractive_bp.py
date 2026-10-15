#!/usr/bin/env python3
"""gen_extractive_bp.py

Extracts APEX payloads and generates clean, precise Android.bp blueprints for
prebuilt and extractive APEX shadow repositories.

Key capabilities:
1. Auto-extracts co-located standard and extractive APEX payloads
   (lib/, lib64/, bin/, share/) to stage alongside dev/static archives.
2. Filters out internal APEX artifacts: _libdummy*, libdummy_*, linker.config.json.
3. Candidate Alignment: When replacing an in-tree component, inspects the candidate
   Android.bp to ensure the generated blueprint provides EXACTLY what the replaced
   candidate provided (e.g. 'libcrypto' for boringssl, 'libprotobuf-cpp-full' /
   'libprotobuf-cpp-lite' / 'aprotoc' for protobuf, 'libchrome' for libchrome).
4. Emits unified cc_prebuilt_library combining matching shared .so and static .a,
   attaching candidate apex_available, min_sdk_version, and export_include_dirs.
5. Intelligently discovers include directories (at root, src/include, dev-src/include)
   and emits candidate-matched header modules without inventing colliding names.
6. Cleans Maven coordinates on JAR files to standard AOSP java_import module names,
   grouping multi-artifact jars cleanly under a single java_import stanza.
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
    name = re.sub(r"\.so(\..*)?$", "", base)
    name = re.sub(r"\.a$", "", name)
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
    seen_keys = set()
    for key, val in props:
        if key in seen_keys:
            continue
        seen_keys.add(key)
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


def extract_blocks(content):
    blocks = []
    i = 0
    n = len(content)
    while i < n:
        m = re.search(r"(\w+)\s*\{", content[i:])
        if not m:
            break
        modtype = m.group(1)
        start_idx = i + m.end() - 1
        depth = 0
        j = start_idx
        in_string = False
        escape = False
        while j < n:
            ch = content[j]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        body = content[start_idx+1:j]
                        blocks.append((modtype, body.strip()))
                        i = j + 1
                        break
            j += 1
        else:
            break
    return blocks


def parse_candidate_bp(cand_path):
    """Parse candidate Android.bp or tree directory to extract module definitions and defaults."""
    if not cand_path:
        return {}
    bp_files = []
    if os.path.isfile(cand_path):
        bp_files = [cand_path]
    elif os.path.isdir(cand_path):
        root_bp = os.path.join(cand_path, "Android.bp")
        if os.path.isfile(root_bp):
            bp_files.append(root_bp)
        for dp, _, fns in os.walk(cand_path):
            for fn in sorted(fns):
                if fn == "Android.bp":
                    full_p = os.path.join(dp, fn)
                    if full_p not in bp_files:
                        bp_files.append(full_p)

    comment_pattern = re.compile(r'("(?:\\.|[^"\\])*")|//[^\r\n]*|/\*[\s\S]*?\*/')
    modules = {}

    for bp in bp_files:
        try:
            with open(bp, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue

        content = comment_pattern.sub(lambda m: m.group(1) if m.group(1) else "", content)

        for mtype, body in extract_blocks(content):
            name_m = re.search(r"name:\s*\"([^\"]+)\"", body)
            if not name_m:
                continue
            mname = name_m.group(1)
            if mname in modules:
                continue

            apex_avail = re.findall(r"apex_available:\s*\[([^\]]*)\]", body)
            avail_list = []
            if apex_avail:
                avail_list = re.findall(r'"([^"]+)"', apex_avail[0])

            host_sup = bool(re.search(r"host_supported:\s*true", body))
            vendor_av = bool(re.search(r"vendor_available:\s*true", body))
            prod_av = bool(re.search(r"product_available:\s*true", body))
            rec_av = bool(re.search(r"recovery_available:\s*true", body))

            sdk_m = re.search(r"min_sdk_version:\s*\"([^\"]+)\"", body)
            sdk_ver = sdk_m.group(1) if sdk_m else None

            inc_m = re.findall(r"export_include_dirs:\s*\[([^\]]*)\]", body)
            inc_list = []
            if inc_m:
                inc_list = re.findall(r'"([^"]+)"', inc_m[0])

            has_srcs = bool(re.search(r"\bsrcs\s*:", body)) or bool(re.search(r"\+\s*[a-zA-Z_]", body)) or bool(re.search(r":\s*[a-zA-Z_]\w*\s*\+", body))

            modules[mname] = {
                "type": mtype,
                "name": mname,
                "apex_available": avail_list,
                "host_supported": host_sup,
                "vendor_available": vendor_av,
                "product_available": prod_av,
                "recovery_available": rec_av,
                "min_sdk_version": sdk_ver,
                "export_include_dirs": inc_list,
                "has_srcs": has_srcs,
                "raw_body": body,
            }
    return modules


def find_candidate_bp(args, root):
    """Locate candidate Android.bp in the platform source tree."""
    if args.candidate_bp and (os.path.isfile(args.candidate_bp) or os.path.isdir(args.candidate_bp)):
        return args.candidate_bp

    tree_candidates = []
    if args.tree_root:
        tree_candidates.append(args.tree_root)
    if "ANDROID_BUILD_TOP" in os.environ:
        tree_candidates.append(os.environ["ANDROID_BUILD_TOP"])
    tree_candidates.append("/home/shadichy/Documents/bliss/los-21")

    upstream = args.upstream
    if not upstream and os.path.isfile(os.path.join(root, "SHADOW.txt")):
        try:
            with open(os.path.join(root, "SHADOW.txt")) as f:
                for line in f:
                    if "upstream:" in line:
                        upstream = line.split("upstream:")[1].strip()
                        break
        except OSError:
            pass

    if upstream:
        for t in tree_candidates:
            # Check upstream directly (file or directory)
            cand = os.path.join(t, upstream, "Android.bp")
            if os.path.isfile(cand):
                return cand
            cand_dir = os.path.join(t, upstream)
            if os.path.isdir(cand_dir):
                return cand_dir
            # Check alternative upstream prefix (e.g. hardware/libchrome vs external/libchrome)
            if upstream.startswith("hardware/"):
                alt = os.path.join(t, "external", upstream[len("hardware/"):], "Android.bp")
                if os.path.isfile(alt):
                    return alt
                alt_dir = os.path.join(t, "external", upstream[len("hardware/"):])
                if os.path.isdir(alt_dir):
                    return alt_dir
            elif upstream.startswith("external/"):
                alt = os.path.join(t, "hardware", upstream[len("external/"):], "Android.bp")
                if os.path.isfile(alt):
                    return alt
                alt_dir = os.path.join(t, "hardware", upstream[len("external/"):])
                if os.path.isdir(alt_dir):
                    return alt_dir
    return None


def generate_blueprint(payloaddir, args):
    root = os.path.abspath(payloaddir)
    if not os.path.isdir(root):
        sys.exit("error: not a directory: %s" % payloaddir)

    raw_name = args.name or os.path.basename(root.rstrip("/")) or "payload"
    name = sanitize(raw_name)
    prefix = args.prefix
    avail = [] if args.no_availability else [(k, True) for k in AVAIL]
    check_elf = [] if args.no_check_elf else [("check_elf_files", False)]

    # Load candidate modules from original candidate Android.bp if available
    cand_bp_path = find_candidate_bp(args, root)
    cand_modules = parse_candidate_bp(cand_bp_path) if cand_bp_path else {}

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
            # Extract to temp, then merge lib/lib64/bin/share into ext_dir
            with tempfile.TemporaryDirectory() as tmp_stage:
                if extract_apex_payload(ap["full_path"], tmp_stage):
                    for sub in ["lib", "lib64", "bin", "share"]:
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
                                elif os.path.isdir(s_item):
                                    shutil.copytree(s_item, d_item, symlinks=True)
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
        hdr = ("// Auto-generated prebuilt Blueprint for %s\n" % name)
    hdr += "// Generated by tools/gen_extractive_bp.py - REVIEW BEFORE USE\n\n"
    hdr += "package {\n    default_applicable_licenses: [%s],\n}\n" % q(args.license)

    # Runtime prebuilt_apex
    for ap in runtime_apexes:
        if ap["is_extractive"] and not args.emit_extractive_prebuilt_apex:
            continue
        lines = [
            "prebuilt_apex {",
            "    name: %s," % q(ap["apex_name"]),
            "    apex_name: %s," % q(ap["apex_name"]),
            "    source_apex_name: %s," % q(ap["apex_name"]),
            "    arch: {",
            "        %s: {" % args.arch,
            "            src: %s," % q(ap["filename"]),
            "        },",
            "    },",
            "    filename: %s," % q(ap["filename"]),
            "    prefer: true,",
            "    installable: true,",
            "}",
        ]
        stanzas.append("\n".join(lines))

    # Candidate classification maps
    cand_cc_libs = {k: v for k, v in cand_modules.items()
                    if v["type"].startswith("cc_library") or v["type"].startswith("cc_prebuilt_library")}
    cand_binaries = {k: v for k, v in cand_modules.items()
                     if v["type"].startswith("cc_binary") or v["type"] == "cc_prebuilt_binary"}
    cand_headers = {k: v for k, v in cand_modules.items()
                    if v["type"] == "cc_library_headers"}

    # Header modules:
    # If candidate Android.bp exists, only emit headers defined by candidate
    # Otherwise, emit canonical <pkg>_headers if primary_inc_dir exists
    emitted_headers = set()
    if cand_headers:
        for ch_name, ch_data in sorted(cand_headers.items()):
            h_props = list(avail)
            apex_av = ch_data["apex_available"] or ["//apex_available:anyapex", "//apex_available:platform"]
            h_props.append(("apex_available", apex_av))
            if primary_inc_dir:
                h_props.append(("export_include_dirs", [primary_inc_dir]))
            stanzas.append(emit("cc_library_headers", modname(ch_name), with_host(h_props)))
            emitted_headers.add(ch_name)
    elif not cand_modules and primary_inc_dir:
        # Fallback only when candidate BP was not provided
        abs_inc = os.path.join(root, primary_inc_dir)
        if args.upstream:
            base_pkg = os.path.basename(args.upstream.rstrip("/"))
        elif raw_name.startswith("prebuilts_target_"):
            base_pkg = raw_name[len("prebuilts_target_"):]
        else:
            base_pkg = raw_name
        main_hdr_name = base_pkg + "_headers" if base_pkg.startswith("lib") else "lib" + base_pkg + "_headers"
        h_props = list(avail)
        if not args.no_apex_available:
            h_props.append(("apex_available", ["//apex_available:anyapex", "//apex_available:platform"]))
        h_props.append(("export_include_dirs", [primary_inc_dir]))
        stanzas.append(emit("cc_library_headers", modname(main_hdr_name), with_host(h_props)))
        emitted_headers.add(main_hdr_name)

    # Helper to choose cleanest source path for given arch
    def best_src(arch_map):
        out = {}
        for a, paths in arch_map.items():
            p_clean = sorted(paths, key=lambda p: (len(p), p))[0]
            out[a] = [p_clean]
        return out

    # Helper to find prebuilt data matching a library name
    def resolve_prebuilt_lib(query_name):
        if query_name in lib_map:
            return query_name, lib_map[query_name]
        # Try stripping suffixes: -cpp-full, -cpp-lite, -cpp, _static, -impl-internal, -internal, -impl
        c = query_name.replace("-cpp-full", "").replace("-cpp-lite", "-lite").replace("-cpp", "")
        for sfx in ["-impl-internal", "-internal", "-impl", "_static", "-static", "_shared", "-shared"]:
            if c.endswith(sfx):
                c = c[:-len(sfx)]
                break
        if c in lib_map:
            return c, lib_map[c]
        if ("lib" + c) in lib_map:
            return ("lib" + c), lib_map["lib" + c]
        if c.startswith("lib") and c[3:] in lib_map:
            return c[3:], lib_map[c[3:]]
        return None, None

    # Emit libraries aligned with candidate modules
    emitted_lib_targets = set()

    def emit_library_module(target_name, data, cand_meta=None):
        sh = data.get("shared", {})
        st = data.get("static", {})
        props = with_host(list(avail) + check_elf)
        if primary_inc_dir:
            props.append(("export_include_dirs", [primary_inc_dir]))
        if not args.no_prefer:
            props.append(("prefer", True))

        # Apex available
        if cand_meta and cand_meta.get("apex_available"):
            props.append(("apex_available", cand_meta["apex_available"]))
        elif not args.no_apex_available:
            props.append(("apex_available", ["//apex_available:anyapex", "//apex_available:platform"]))

        # Min SDK version
        if cand_meta and cand_meta.get("min_sdk_version"):
            props.append(("min_sdk_version", cand_meta["min_sdk_version"]))
        else:
            props.append(("min_sdk_version", "29"))

        # Vendor / product availability from candidate
        if cand_meta:
            if cand_meta.get("vendor_available"):
                props.append(("vendor_available", True))
            if cand_meta.get("product_available"):
                props.append(("product_available", True))
            if cand_meta.get("recovery_available"):
                props.append(("recovery_available", True))

        # Deduplicate properties by key
        dedup_props = []
        seen = set()
        for k, v in props:
            if k in seen:
                continue
            seen.add(k)
            dedup_props.append((k, v))
        props = dedup_props

        # Determine target mode based on candidate type
        cand_type = cand_meta.get("type", "") if cand_meta else ""
        force_static = (cand_type in ("cc_library_static", "cc_prebuilt_library_static") or
                        target_name.endswith("_static") or "-impl-internal" in target_name)
        force_shared = (cand_type in ("cc_library_shared", "cc_prebuilt_library_shared"))

        if force_static and (st or sh):
            lines = ["cc_prebuilt_library_static {", "    name: %s," % q(modname(target_name))]
            for k, v in props:
                rendered = prop(k, v)
                if rendered:
                    lines.append(rendered)
            st_src = best_src(st if st else sh)
            if args.flat_srcs or len(st_src) == 1 and args.arch in st_src:
                lines.append("    srcs: [%s]," % q(st_src[args.arch][0]))
            else:
                lines.extend(emit_arch_srcs(st_src))
            lines.append("}")
            stanzas.append("\n".join(lines))
        elif force_shared and (sh or st):
            lines = ["cc_prebuilt_library_shared {", "    name: %s," % q(modname(target_name))]
            for k, v in props:
                rendered = prop(k, v)
                if rendered:
                    lines.append(rendered)
            sh_src = best_src(sh if sh else st)
            if args.flat_srcs or len(sh_src) == 1 and args.arch in sh_src:
                lines.append("    srcs: [%s]," % q(sh_src[args.arch][0]))
            else:
                lines.extend(emit_arch_srcs(sh_src))
            lines.append("}")
            stanzas.append("\n".join(lines))
        elif sh and st:
            lines = ["cc_prebuilt_library {", "    name: %s," % q(modname(target_name))]
            for k, v in props:
                rendered = prop(k, v)
                if rendered:
                    lines.append(rendered)
            sh_src = best_src(sh)
            lines.append("    shared: {")
            if args.flat_srcs or len(sh_src) == 1 and args.arch in sh_src:
                lines.append("        srcs: [%s]," % q(sh_src[args.arch][0]))
            else:
                lines.extend(emit_arch_srcs(sh_src, indent="        "))
            lines.append("    },")
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
            lines = ["cc_prebuilt_library_shared {", "    name: %s," % q(modname(target_name))]
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
            lines = ["cc_prebuilt_library_static {", "    name: %s," % q(modname(target_name))]
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

    # Match candidate libraries first
    matched_prebuilts = set()
    for cand_name, cand_data in sorted(cand_cc_libs.items()):
        matched_key, pdata = resolve_prebuilt_lib(cand_name)
        if pdata:
            emit_library_module(cand_name, pdata, cand_data)
            emitted_lib_targets.add(cand_name)
            matched_prebuilts.add(matched_key)

    # Emit remaining prebuilt libraries
    for libname, data in sorted(lib_map.items()):
        if libname not in emitted_lib_targets:
            emit_library_module(libname, data)
            emitted_lib_targets.add(libname)

    # Java imports (Clean Maven naming, grouped by module name)
    jars_by_name = {}
    for rel in sorted(jars):
        clean_name = clean_jar_name(rel)
        jars_by_name.setdefault(clean_name, []).append(rel)

    for mod_name, jar_list in sorted(jars_by_name.items()):
        props = with_host([("jars", sorted(jar_list)), ("host_supported", True)])
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

    # Helper to resolve prebuilt binary
    def resolve_prebuilt_bin(query_name):
        if query_name in binaries:
            return query_name, binaries[query_name]
        if query_name.startswith("a") and query_name[1:] in binaries:
            return query_name[1:], binaries[query_name[1:]]
        return None, None

    # Binaries (Aligned with candidate modules)
    emitted_bins = set()
    for cand_name, cand_data in sorted(cand_binaries.items()):
        matched_key, arch_srcs = resolve_prebuilt_bin(cand_name)
        if arch_srcs:
            props = with_host(check_elf + ([] if args.no_prefer else [("prefer", True)]))
            lines = ["cc_prebuilt_binary {", "    name: %s," % q(modname(cand_name))]
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
            emitted_bins.add(cand_name)
            emitted_bins.add(matched_key)

    for base, arch_srcs in sorted(binaries.items()):
        if base in emitted_bins:
            continue
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
        emitted_bins.add(base)

    # Candidate Defaults (preserve essential interface defaults without sources)
    cand_defaults = {k: v for k, v in cand_modules.items()
                     if v["type"].endswith("_defaults") and not v["has_srcs"]}
    for dname, ddata in sorted(cand_defaults.items()):
        d_type = "cc_defaults" if ddata["type"].endswith("cc_defaults") else ddata["type"]
        lines = ["%s {" % d_type, "    name: %s," % q(modname(dname))]
        for line in ddata["raw_body"].splitlines():
            s = line.strip()
            if s.startswith("name:"):
                continue
            if s:
                lines.append("    " + s)
        lines.append("}")
        stanzas.append("\n".join(lines))

    # Scripts (Deduplicated by base name, preferring src/)
    seen_scripts = set()
    for rel in sorted(scripts, key=lambda s: (0 if s.startswith("src/") else 1, s)):
        base = re.sub(r"\.sh$", "", os.path.basename(rel))
        if base in seen_scripts:
            continue
        seen_scripts.add(base)
        stanzas.append(emit("sh_binary", modname(base), with_host([("src", rel)])))

    # etc (Excluding linker.config.json)
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
    ap.add_argument("--candidate-bp", default=None,
                    help="path to original candidate Android.bp to match module names and properties")
    ap.add_argument("--tree-root", default=None,
                    help="path to platform source tree root")
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
