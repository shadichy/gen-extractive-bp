#!/usr/bin/env python3
"""Generate an extractive APEX payload Android.bp by scanning a staging dir.

Walks a payload tree ($pkgdirprefix layout: lib64/, lib/, bin/, share/,
include/, etc/, *.apk) and emits Soong modules in the exact style of the
fleet's extractive APEX blueprints (see apex/apache-xml, apex/core,
apex/expat, apex/dmidecode), reusing the emitter conventions of
/tmp/opencode/gen_extractive.py and gen_androidx.py:

  lib64/*.so, lib/*.so (+ versioned .so.*) -> cc_prebuilt_library_shared
  *.a                                      -> cc_prebuilt_library_static
  *.jar                                    -> java_import
  *.apk                                    -> android_app_import
  ELF executables                          -> cc_prebuilt_binary
  shell scripts (shebang + exec bit)       -> sh_binary
  *.h/*.hpp (grouped by dir)               -> cc_library_headers <lib>_headers
  etc/** (default on, --no-etc to skip)    -> prebuilt_etc (per file)
  *.apex                                   -> prebuilt_apex (full ext form)

REVIEW THE OUTPUT BEFORE USE:
  - .so symlink chains collapse to ONE module named after the shortest link
    name, srcs pointing at the real file (no versioned-.so precedent exists
    in-tree; adjust DT_SONAME needs by hand).
  - android_app_import defaults to presigned: true; pass --certificate to
    re-sign instead.
  - Module names keep upstream sonames for linking. The 'ext' prefix lives
    on the APEX *package* (org.blisslabs.ag.ext.<name>), not on bp modules.

Usage:
  gen_extractive_bp.py PAYLOAD_DIR [-o Android.bp] [options]
"""
import argparse
import os
import re
import sys

HEADER_EXTS = (".h", ".hpp", ".hh", ".hxx", ".h++")
APEX_RE = re.compile(r"\.apex$", re.IGNORECASE)
AVAIL = ["vendor_available", "product_available", "recovery_available",
         "host_supported"]


def q(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def sanitize(name):
    """Soong-safe module name, extractive style: dots and dashes become
    underscores (cf. gen_extractive sharename.replace + androidx_core)."""
    name = re.sub(r"[.\-]", "_", name)
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    name = name.strip("_") or "unnamed"
    if name[0].isdigit():
        name = "m_" + name
    return re.sub(r"_+", "_", name)


def soname_of(filename):
    m = re.match(r"^(.+?)\.so(\..*)?$", filename)
    if m:
        return m.group(1)
    m = re.match(r"^(.+?)\.a$", filename)
    return m.group(1) if m else filename


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


def prop(key, val, indent="    "):
    """Render one property line or list block."""
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


def emit_arch_srcs(srcs, arch):
    """arch: { <arch>: { srcs: [...] } } block lines (core extractive style)."""
    lines = ["    arch: {", "        %s: {" % arch, "            srcs: ["]
    lines += ["                %s," % q(s) for s in srcs]
    lines += ["            ],", "        },", "    },"]
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("payloaddir")
    ap.add_argument("-o", "--output", default="-")
    ap.add_argument("--name", default=None,
                    help="payload name (default: dir basename)")
    ap.add_argument("--upstream", default=None,
                    help="upstream path for header comment "
                         "(// Auto-generated prebuilt Blueprint for <path>)")
    ap.add_argument("--apex-pkg", default=None,
                    help="extractive APEX package for header comment "
                         "(// Extracted from Extractive APEX package: <pkg>)")
    ap.add_argument("--prefix", default="",
                    help="prefix for generated module names")
    ap.add_argument("--license", default="Android-Apache-2.0")
    ap.add_argument("--arch", default="x86_64",
                    help="arch key for arch-map srcs (core style)")
    ap.add_argument("--flat-srcs", action="store_true",
                    help="plain top-level srcs instead of arch map (expat style)")
    ap.add_argument("--certificate", default=None,
                    help="android_app_import certificate (default: presigned)")
    ap.add_argument("--no-availability", action="store_true",
                    help="drop vendor/product/recovery/host_supported props")
    ap.add_argument("--no-prefer", action="store_true",
                    help="drop prefer: true")
    ap.add_argument("--no-check-elf", action="store_true",
                    help="drop check_elf_files: false")
    ap.add_argument("--no-apex-available", action="store_true",
                    help="drop apex_available from headers modules")
    ap.add_argument("--etc", dest="etc", action="store_true", default=True)
    ap.add_argument("--no-etc", dest="etc", action="store_false")
    args = ap.parse_args()

    root = os.path.abspath(args.payloaddir)
    if not os.path.isdir(root):
        sys.exit("error: not a directory: %s" % args.payloaddir)
    raw_name = args.name or os.path.basename(root.rstrip("/")) or "payload"
    name = sanitize(raw_name)
    prefix = args.prefix
    avail = [] if args.no_availability else [(k, True) for k in AVAIL]
    prefer = [] if args.no_prefer else [("prefer", True)]
    check_elf = [] if args.no_check_elf else [("check_elf_files", False)]

    def modname(base):
        return prefix + sanitize(base)

    # ---- walk ----
    files = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                try:
                    target = os.path.realpath(full)
                    if os.path.isfile(target):
                        files.append((rel, os.path.relpath(target, root)))
                    else:
                        print("warning: skipping broken symlink: %s" % rel,
                              file=sys.stderr)
                except OSError as e:
                    print("warning: skipping %s: %s" % (rel, e), file=sys.stderr)
            elif os.path.isfile(full):
                files.append((rel, None))

    # ---- classify ----
    so_links = {}    # real target rel -> [link rels]
    so_plain = []    # .so files that are no chain target
    statics, jars, apks, binaries, scripts, apexes, etcs = ([] for _ in range(7))
    header_groups = {}  # group -> set(dirs)
    skipped = []

    targets = set(t for _, t in files
                  if t and re.search(r"\.so(\..*)?$", os.path.basename(t)))
    for rel, target in files:
        full = os.path.join(root, rel)
        base = os.path.basename(rel)
        if APEX_RE.search(base):
            apexes.append(rel)
            continue
        if re.search(r"\.so(\..*)?$", base):
            if target:
                so_links.setdefault(target, []).append(rel)
            elif rel in targets:
                pass  # chain real file; emitted via its link
            else:
                so_plain.append(rel)
            continue
        if base.endswith(".a"):
            statics.append(rel)
            continue
        if base.endswith(".jar"):
            jars.append(rel)
            continue
        if base.endswith(".apk"):
            apks.append(rel)
            continue
        if args.etc and (rel == "etc" or rel.startswith("etc/")):
            if os.path.basename(rel) != "etc":
                etcs.append(rel)
                continue
        if base.endswith(HEADER_EXTS):
            d = os.path.dirname(rel) or "."
            parts = d.split(os.sep)
            if parts[0] == "include" and len(parts) > 1:
                group = parts[1]
            else:
                group = parts[0]
            header_groups.setdefault(group, set()).add(d)
            continue
        if base == "NOTICE":
            continue  # consumed by the license stanza below
        if os.access(full, os.X_OK):
            if is_elf(full):
                binaries.append(rel)
                continue
            if is_script(full):
                scripts.append(rel)
                continue
        skipped.append(rel)

    stanzas = []
    used = {}

    def unique(base):
        n, i = base, 2
        while n in used:
            n = "%s_%d" % (base, i)
            i += 1
        used[n] = True
        return n

    # ---- header + package (+ NOTICE license) ----
    if args.upstream:
        hdr = ("// Auto-generated prebuilt Blueprint for %s\n" % args.upstream)
    else:
        hdr = ("// Auto-generated prebuilt Blueprint for %s\n" % raw_name)
    if args.apex_pkg:
        hdr += ("// Extracted from Extractive APEX package: %s\n"
                % args.apex_pkg)
    hdr += ("// Generated by tools/gen_extractive_bp.py - REVIEW BEFORE USE\n"
            "\n")
    notice = os.path.isfile(os.path.join(root, "NOTICE"))
    if notice:
        lic_name = sanitize(name + "_license")
        hdr += ("package {\n"
                "    default_applicable_licenses: [%s],\n"
                "}\n"
                "\n"
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

    # ---- prebuilt_apex (full ext form, cf. gen_androidx BP_TEMPLATE) ----
    for rel in sorted(apexes):
        base = os.path.basename(rel)
        stem = APEX_RE.sub("", base)
        installable = not re.search(r"\.(dev|doc)$", stem, re.IGNORECASE)
        lines = ["prebuilt_apex {",
                 "    name: %s," % q(unique(modname(stem))),
                 "    apex_name: %s," % q(stem),
                 "    source_apex_name: %s," % q(stem),
                 "    arch: {",
                 "        %s: {" % args.arch,
                 "            src: %s," % q(rel),
                 "        },",
                 "    },",
                 "    filename: %s," % q(base)]
        if not args.no_prefer:
            lines.append("    prefer: true,")
        lines.append("    installable: %s," % ("true" if installable else "false"))
        lines.append("}")
        stanzas.append("\n".join(lines))

    # ---- shared libs ----
    def shared_stanza(link_rel, target_rel):
        props = list(avail) + check_elf
        stanza = ["cc_prebuilt_library_shared {",
                  "    name: %s,"
                  % q(unique(modname(soname_of(os.path.basename(link_rel)))))]
        for key, val in props:
            stanza.append(prop(key, val))
        if args.flat_srcs:
            stanza.append(prop("srcs", [target_rel]))
        else:
            stanza.extend(emit_arch_srcs([target_rel], args.arch))
        stanza += [p for p in [prop("prefer", True)] if not args.no_prefer]
        stanza.append("}")
        return "\n".join(stanza)

    for target in sorted(so_links):
        link = min(sorted(so_links[target]),
                   key=lambda l: (len(os.path.basename(l)), os.path.basename(l)))
        stanzas.append(shared_stanza(link, target))
    for rel in sorted(so_plain):
        stanzas.append(shared_stanza(rel, rel))

    # ---- static libs (core style) ----
    for rel in sorted(statics):
        lines = ["cc_prebuilt_library_static {",
                 "    name: %s,"
                 % q(unique(modname(soname_of(os.path.basename(rel)))))]
        for key, val in avail:
            lines.append(prop(key, val))
        if args.flat_srcs:
            lines.append(prop("srcs", [rel]))
        else:
            lines.extend(emit_arch_srcs([rel], args.arch))
        if not args.no_prefer:
            lines.append(prop("prefer", True))
        lines.append("}")
        stanzas.append("\n".join(lines))

    # ---- jars (gen_extractive IMPORT_TEMPLATE + prefer) ----
    for rel in sorted(jars):
        base = os.path.basename(rel)
        props = [("jars", [rel]), ("host_supported", True)]
        if not args.no_prefer:
            props.append(("prefer", True))
        stanzas.append(emit("java_import",
                            unique(modname(re.sub(r"\.jar$", "", base))),
                            props))

    # ---- apks ----
    for rel in sorted(apks):
        base = os.path.basename(rel)
        props = [("apk", rel)]
        if args.certificate:
            props.append(("certificate", args.certificate))
        else:
            props.append(("presigned", True))
        stanzas.append(emit("android_app_import",
                            unique(modname(re.sub(r"\.apk$", "", base))),
                            props))

    # ---- binaries / scripts (dmidecode style) ----
    for rel in sorted(binaries):
        props = (check_elf +
                 [("srcs", [rel])] +
                 ([] if args.no_prefer else [("prefer", True)]))
        stanzas.append(emit("cc_prebuilt_binary",
                            unique(modname(os.path.basename(rel))), props))
    for rel in sorted(scripts):
        base = os.path.basename(rel)
        base = re.sub(r"\.sh$", "", base)
        stanzas.append(emit("sh_binary",
                            unique(modname(base)),
                            [("src", rel)]))

    # ---- headers, one <group>_headers module per dir group ----
    for group in sorted(header_groups):
        dirs = sorted(header_groups[group])
        props = list(avail)
        if not args.no_apex_available:
            props.append(("apex_available", ["//apex_available:anyapex",
                                             "//apex_available:platform"]))
        props.append(("export_include_dirs", dirs))
        stanzas.append(emit("cc_library_headers",
                            unique(modname(group + "_headers")), props))

    # ---- etc ----
    for rel in sorted(etcs):
        sub = os.path.dirname(os.path.relpath(rel, "etc"))
        props = [("src", rel)]
        if sub and sub != ".":
            props.append(("sub_dir", sub))
        stanzas.append(emit("prebuilt_etc",
                            unique(modname(os.path.basename(rel))), props))

    out = hdr + ("\n" + "\n\n".join(stanzas) + "\n" if stanzas else "\n")
    if not out.endswith("\n"):
        out += "\n"

    for rel in skipped:
        print("warning: skipped (no module type): %s" % rel, file=sys.stderr)
    n_hdr_dirs = sum(len(v) for v in header_groups.values())
    print("info: %d modules, %d skipped, %d header dirs" %
          (len(stanzas), len(skipped), n_hdr_dirs), file=sys.stderr)

    if args.output == "-":
        sys.stdout.write(out)
    else:
        with open(args.output, "w") as f:
            f.write(out)


if __name__ == "__main__":
    main()
