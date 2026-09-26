#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic sandbox provisioner (NIGHT-think-1) — the rootless builder
for the local KVM micro-VM.

The CI micro-VM (.github/workflows/supermassive.yml) assembles its
rootfs with docker on a hosted runner; this provisioner builds the
SAME shape on a developer box or agent sandbox with NOTHING but
curl, python3, and git — no docker, no host root:

  * kernel: resolved dynamically from the archives (floor = the
    impish 5.13.0-* kernel on the frozen old-releases mirror, the
    documented minimum; lts = the newest Ubuntu LTS suite's kernel
    across its main/updates/security pockets; latest = the archive's
    newest generic kernel across the two newest suites), extracted
    from the .deb with a pure-python ar reader — no binutils needed.
  * rootfs: the ubuntu:22.04 base tarball (glibc 2.35 boots on any
    kernel >= 3.2, the same userland the CI VM holds constant on
    purpose) plus python3 / iproute2 / curl provisioned by REAL
    dependency resolution against the jammy Packages index — every
    closure .deb downloaded and data.tar extracted rootless.
  * initramfs: packed as a newc cpio by this file itself, with the
    device nodes a non-root packer cannot mknod (console, null,
    tty, ttyS0) synthesized directly into the archive stream, the
    repo checkout (git archive HEAD) at /opt/zelynic, the static
    musl zelynic binary beside it, and sandbox-init.sh as /init.

The 644/755 permission discipline is enforced at pack time: every
regular file lands 0644 unless executable (0755), every directory
0755 — the image inherits the repo's own rule.

Usage (the bash entrypoint scripts/sandbox/zelynic-sandbox.sh owns
the orchestration; these subcommands are its legs):
  python3 scripts/sandbox/rootfs-pack.py kernel --suite floor  --cache DIR
  python3 scripts/sandbox/rootfs-pack.py initrd --cache DIR --repo DIR \
      --binary PATH --init PATH [--payload PATH]
  python3 scripts/sandbox/rootfs-pack.py self-test
"""

import argparse
import gzip
import io
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from email.utils import parsedate_to_datetime

UBUNTU_BASE_URL = "http://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/"
UBUNTU_BASE_PINNED = "ubuntu-base-22.04.5-base-amd64.tar.gz"
JAMMY_PACKAGES = "http://archive.ubuntu.com/ubuntu/dists/jammy/main/binary-amd64/Packages.gz"
ARCHIVE_POOL = "http://archive.ubuntu.com/ubuntu/"
OLD_RELEASES_LINUX_POOL = "http://old-releases.ubuntu.com/ubuntu/pool/main/l/linux/"
ARCHIVE_DIST = "http://archive.ubuntu.com/ubuntu/dists/"
FLOOR_KERNEL_RE = re.compile(r"linux-image-unsigned-5\.13\.0-[0-9]+-generic_[^\"']*?_amd64\.deb")
LATEST_KERNEL_PKG_RE = re.compile(
    r"^linux-image-unsigned-([0-9]+)\.([0-9]+)\.([0-9]+)-([0-9]+)-generic$"
)
ROOT_PACKAGES = ["python3", "iproute2", "curl"]


def http_get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def http_get_text(url, timeout=120):
    return http_get(url, timeout).decode("utf-8", "replace")


def http_get_gz_text(url, timeout=120):
    return gzip.decompress(http_get(url, timeout)).decode("utf-8", "replace")


def download_atomic(url, dest, timeout=600):
    """Fetch url into dest ATOMICALLY: the bytes land in a .part twin
    and only a completed transfer renames over dest — an interrupted
    run (Ctrl-C, a killed agent shell, a full disk) can never leave a
    partial file behind (NIGHT-harness-1: a killed first run left a
    0-byte deb that every warm-cache retry then treated as complete
    and died on mid-extraction)."""
    part = f"{dest}.part"
    with open(part, "wb") as fh:
        fh.write(http_get(url, timeout=timeout))
    os.replace(part, dest)
    return dest


def _intact_deb(path):
    """The ar magic is the cheapest possible integrity gate: a cached
    .deb whose first 8 bytes are not the ar magic is a truncated or
    empty leftover and gets re-fetched instead of trusted."""
    try:
        with open(path, "rb") as fh:
            return fh.read(8) == b"!<arch>\n"
    except OSError:
        return False


def say(msg):
    # Progress notes ride STDERR (NIGHT-blade-10): the entrypoint
    # captures this script's stdout in a command substitution to get
    # the vmlinuz/initrd PATH — a note on stdout pollutes the capture
    # and the [ -f "$path" ] check dies on a multi-line string (the
    # first-ever, uncached kernel resolution could never boot through
    # the entrypoint; only warm caches hid it).
    print(f"[sandbox-pack] {msg}", file=sys.stderr, flush=True)


# ── ar archive reader (an ar file is a flat sequence of 60-byte ─────────────
#    headers after the 8-byte "!<arch>\n" magic — a .deb is an ar whose
#    data.tar member is the filesystem payload).


def ar_members(deb_bytes):
    """Yield (name, payload_bytes) for every member of an ar archive."""
    if deb_bytes[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive (bad magic)")
    off = 8
    while off + 60 <= len(deb_bytes):
        hdr = deb_bytes[off : off + 60]
        name = hdr[0:16].decode("ascii", "replace").rstrip()
        size = int(hdr[48:58].decode("ascii").strip())
        off += 60
        payload = deb_bytes[off : off + size]
        off += size
        if off % 2:  # members are 2-byte aligned
            off += 1
        yield name, payload


def _zstd_decompress(data):
    """Layered zstd decompression (Ubuntu ships kernel debs as
    data.tar.zst — streaming frames, often without a content size in
    the frame header, so the STREAMING reader is mandatory): the
    python 3.14+ stdlib module first, then the zstandard pip module,
    then the zstd CLI — and a clear error naming the fix when none is
    present."""
    try:
        import compression.zstd as _z  # python 3.14+: stdlib

        return _z.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    except ImportError:
        pass
    try:
        import zstandard as _zstd  # pip install zstandard

        return _zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
    except ImportError:
        pass
    import subprocess

    for cmd in ("unzstd", "zstd"):
        if shutil.which(cmd):
            return subprocess.run(
                [cmd, "-dc"], input=data, stdout=subprocess.PIPE, check=True
            ).stdout
    raise SystemExit(
        "this .deb's data.tar.zst needs a zstd decompressor: python 3.14+ "
        "(compression.zstd), `pip install zstandard`, or the zstd CLI"
    )


def deb_data_tar(deb_bytes):
    """The data.tar.* member of a .deb, decompressed to bytes."""
    for name, payload in ar_members(deb_bytes):
        if name.startswith("data.tar"):
            if name.endswith(".xz"):
                return lzma.decompress(payload)
            if name.endswith(".gz"):
                return gzip.decompress(payload)
            if name.endswith(".zst"):
                return _zstd_decompress(payload)
            if name.endswith(".tar"):
                return payload
            raise ValueError(f"unsupported data.tar compression: {name}")
    raise ValueError("no data.tar member in deb")


def extract_tar_bytes_into(data, rootfs):
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        try:
            tar.extractall(rootfs, filter="fully_trusted")
        except TypeError:  # python < 3.12: no filter kwarg
            tar.extractall(rootfs)


def extract_deb_into(deb_path, rootfs):
    """Extract a .deb's data.tar into rootfs/ (rootless; the content is
    the Ubuntu archive's own, addressed by the Packages index)."""
    with open(deb_path, "rb") as fh:
        data = deb_data_tar(fh.read())
    extract_tar_bytes_into(data, rootfs)


# ── newc cpio writer ────────────────────────────────────────────────────────
#
# The newc format per entry: 110-byte ASCII header (magic 070701 + 13
# eight-digit hex fields), NUL-terminated name padded to a 4-byte
# boundary, then the file data (also padded). The archive ends with a
# TRAILER!!! entry. Device nodes ride as mode S_IFCHR with rdev
# major/minor — the one thing a rootless filesystem walk cannot
# produce, which is exactly why this packer exists.


def _newc_header(ino, mode, filesize, rdevmajor, rdevminor, namesize):
    def h(v):
        return f"{v:08X}"

    return (
        b"070701"
        + h(ino).encode()
        + h(mode).encode()
        + h(0).encode()  # uid: root
        + h(0).encode()  # gid: root
        + h(1).encode()  # nlink
        + h(0).encode()  # mtime: 0 for deterministic images
        + h(filesize).encode()
        + h(0).encode()  # devmajor
        + h(0).encode()  # devminor
        + h(rdevmajor).encode()
        + h(rdevminor).encode()
        + h(namesize).encode()
        + h(0).encode()  # check: 0 = no checksum
    )


def _newc_entry(out, ino, name, mode, data, rdevmajor=0, rdevminor=0):
    """name is the archive path WITHOUT leading slash ('dev/console').

    NIGHT-blade-10 alignment fix: the newc spec pads the (header +
    name) span to a 4-byte boundary — and the header is 110 bytes,
    110 % 4 == 2, so the name padding must absorb the header's own
    2-byte remainder. The former `(-len(raw)) % 4` pad aligned the
    name alone; every entry whose name length left the true offset
    misaligned shipped broken padding. Old kernels (the 5.13 floor
    lane) tolerated it — the initramfs scanner just skips bad bytes
    — but modern kernels (6.12+ strictness, the 7.0 LTS lane
    included) FAIL the unpack: "Initramfs unpacking failed: broken
    padding", PID 1 never runs, VFS panics on the missing root.
    The data padding is correct as-is: with the span aligned, the
    data starts 4-aligned."""
    raw = name.encode() + b"\x00"
    out.write(_newc_header(ino, mode, len(data), rdevmajor, rdevminor, len(raw)))
    out.write(raw)
    out.write(b"\x00" * ((-(110 + len(raw))) % 4))
    if data:
        out.write(data)
        out.write(b"\x00" * ((-len(data)) % 4))


def _newc_trailer(out):
    _newc_entry(out, 0, "TRAILER!!!", 0o100644, b"")
    out.write(b"\x00" * ((-out.tell()) % 4))


# The device nodes a direct-boot guest needs before devtmpfs mounts:
# the kernel opens /dev/console for PID 1's stdio, and a handful of
# classics keep early init simple (devtmpfs populates the rest).
SYNTH_DEVICES = {
    "dev/console": (5, 1),
    "dev/null": (1, 3),
    "dev/tty": (5, 0),
    "dev/ttyS0": (4, 64),
}


def pack_initramfs(rootfs, out_path):
    """Walk rootfs/ and emit the gzipped newc cpio. Dirs 0755, files
    0644 (0755 when any exec bit is set), symlinks 120777, synthesized
    char devices for SYNTH_DEVICES — the 644/755 discipline, enforced."""
    ino = 1
    buffer = io.BytesIO()
    emitted = set()
    # The root itself first (cpio archives begin with ".").
    _newc_entry(buffer, ino, ".", 0o040755, b"")
    ino += 1
    for dirpath, dirnames, filenames in os.walk(rootfs, followlinks=False):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, rootfs)
        for name in sorted(dirnames):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                # NIGHT-blade-10: os.walk classifies a
                # symlink-TO-A-DIRECTORY as a dirname (entry.is_dir()
                # follows links), and emitting it as 040755 shipped
                # an EMPTY directory — the usr-merge layout
                # (/bin -> usr/bin, /lib -> usr/lib, /lib64 ->
                # usr/lib64 in every modern ubuntu base) was deleted
                # from the image, the dynamic linker vanished with
                # /lib64, and PID 1 died "Failed to execute /init
                # (error -2)" before a single line of init ran. The
                # link itself is the entry; followlinks=False already
                # guarantees the target tree is walked exactly once
                # through its real parent.
                _newc_entry(buffer, ino, rel, 0o120777, os.readlink(full).encode())
            else:
                _newc_entry(buffer, ino, rel, 0o040755, b"")
            emitted.add(rel)
            ino += 1
        for name in sorted(filenames):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                _newc_entry(buffer, ino, rel, 0o120777, os.readlink(full).encode())
                emitted.add(rel)
                ino += 1
                continue
            if rel in SYNTH_DEVICES:
                major, minor = SYNTH_DEVICES[rel]
                _newc_entry(buffer, ino, rel, 0o020600, b"", major, minor)
                emitted.add(rel)
                ino += 1
                continue
            # A non-root tar extraction degrades device nodes to empty
            # placeholder files under /dev — the synthesized set above
            # carries the real nodes, so the placeholders are dropped.
            if rel.startswith("dev/") and os.path.getsize(full) == 0:
                continue
            mode = 0o100755 if os.access(full, os.X_OK) else 0o100644
            with open(full, "rb") as fh:
                data = fh.read()
            _newc_entry(buffer, ino, rel, mode, data)
            emitted.add(rel)
            ino += 1
    # The synthesized device set is guaranteed COMPLETE regardless of
    # what the base tarball shipped or degraded: any SYNTH_DEVICES path
    # the walk did not emit lands here (the base image carries no
    # dev/console entry at all — a rootless extract could never mknod
    # one).
    for rel in sorted(SYNTH_DEVICES):
        if rel in emitted:
            continue
        major, minor = SYNTH_DEVICES[rel]
        _newc_entry(buffer, ino, rel, 0o020600, b"", major, minor)
        ino += 1
    _newc_trailer(buffer)
    with gzip.GzipFile(out_path, "wb", mtime=0) as gz:
        gz.write(buffer.getvalue())


# ── dependency resolution (the jammy Packages index is the truth) ──────────


def parse_packages(gz_bytes):
    """Packages.gz -> {name: {"version":, "depends": [...], "filename":}}."""
    text = gzip.decompress(gz_bytes).decode("utf-8", "replace")
    index = {}
    for stanza in re.split(r"\n\n+", text):
        name = version = filename = None
        depends = []
        for line in stanza.splitlines():
            if line.startswith("Package: "):
                name = line[9:].strip()
            elif line.startswith("Version: "):
                version = line[9:].strip()
            elif line.startswith("Filename: "):
                filename = line[10:].strip()
            elif line.startswith(("Depends: ", "Pre-Depends: ")):
                depends.append(line.split(": ", 1)[1])
        if name and filename:
            index[name] = {"version": version, "filename": filename, "depends": depends}
    return index


def dep_names(depends_lines):
    """First alternative of every dependency clause, versions stripped."""
    names = []
    for line in depends_lines:
        for clause in line.split(","):
            clause = clause.strip()
            if not clause:
                continue
            first = clause.split("|")[0].strip()
            name = first.split(" ")[0].split(":")[0]
            if name:
                names.append(name)
    return names


def resolve_closure(index, roots):
    """Every package the roots need, transitively (first-alternative
    policy — the conservative choice for a pinned archive)."""
    seen, ordered, queue = set(), [], list(roots)
    while queue:
        name = queue.pop(0)
        if name in seen or name not in index:
            continue
        seen.add(name)
        ordered.append(name)
        queue.extend(dep_names(index[name]["depends"]))
    return ordered


# ── kernel resolution (NIGHT-blade-10: archive-native end to end) ───────────
#
# The dists/ index names the pocket directories that actually exist,
# and every Release file carries a Version: field — the LTS cadence
# reads straight off it (YY.04 with an even YY, every time, by the
# published cadence; the unreleased 'devel' alias is excluded by
# name until release day). The former codename-based 'latest' path
# 404'd whenever the devel suite led the date sort — its codename
# has no dists/ directory until release — and the date sort itself
# compared RFC-2822 strings, where the weekday prefix outranks the
# calendar ("Thu, 23 Apr" sorts above "Sat, 26 Sep"). Both fixed.

LTS_VERSION_RE = re.compile(r"^([0-9]{2})\.04$")
DEVEL_ALIAS = "devel"


def dists_suite_dirs():
    """Every suite directory the archive exposes (base suites and
    pockets alike — the directories are the fetchable truth)."""
    dist = http_get_text(ARCHIVE_DIST, timeout=120)
    return sorted({m for m in re.findall(r'href="([a-z0-9-]+)/"', dist)})


def suite_meta(suite_dir):
    """Version/Date from a suite's Release file; None when the suite
    carries no Version field or the fetch fails (a dead pocket is a
    skip, not a stop)."""
    try:
        rel = http_get_text(f"{ARCHIVE_DIST}{suite_dir}/Release", timeout=60)
    except Exception:  # noqa: BLE001
        return None
    version = re.search(r"^Version: (.+)$", rel, re.M)
    date = re.search(r"^Date: (.+)$", rel, re.M)
    if not (version and date):
        return None
    try:
        when = parsedate_to_datetime(date.group(1).strip())
    except Exception:  # noqa: BLE001 - a malformed date is a skip
        return None
    return {"version": version.group(1).strip(), "date": when}


def version_key(version):
    """'26.04' -> (26, 4) for cadence-safe ordering; None when the
    field is not a numeric YY.MM."""
    try:
        return tuple(int(x) for x in version.split("."))
    except ValueError:
        return None


def kernel_candidates(text):
    """(version_tuple, pool_filename) for every generic unsigned
    kernel image in a Packages index stanza set."""
    out = []
    for stanza in re.split(r"\n\n+", text):
        name = re.search(r"^Package: (.+)$", stanza, re.M)
        if not name:
            continue
        match = LATEST_KERNEL_PKG_RE.match(name.group(1).strip())
        if not match:
            continue
        filename = re.search(r"^Filename: (.+)$", stanza, re.M)
        if not filename:
            continue
        out.append((tuple(int(x) for x in match.groups()), filename.group(1).strip()))
    return out


def resolve_kernel(suite_dir):
    """The newest generic kernel across a suite's main, -updates and
    -security pockets (-proposed excluded): the documented 'newest
    kernel, updates included' contract, finally true in code."""
    best = None
    for pocket in (suite_dir, f"{suite_dir}-updates", f"{suite_dir}-security"):
        try:
            text = http_get_gz_text(
                f"{ARCHIVE_DIST}{pocket}/main/binary-amd64/Packages.gz", timeout=300
            )
        except Exception as e:  # noqa: BLE001
            say(f"  pocket {pocket} unreachable ({e}) — skipped")
            continue
        for cand in kernel_candidates(text):
            if best is None or cand[0] > best[0]:
                best = cand
    return best


def fetch_kernel(suite, cache):
    """Resolve + download + extract the vmlinuz for the suite; returns
    the cached path. floor = impish 5.13.0-* (the documented minimum,
    a frozen archive); lts = the newest Ubuntu LTS suite's kernel
    across its main/updates/security pockets; latest = the archive's
    newest generic kernel across the two newest suites."""
    out = os.path.join(cache, f"vmlinuz-{suite}")
    if os.path.exists(out):
        return out
    if suite == "floor":
        say("resolving the impish 5.13 floor kernel (old-releases pool)...")
        hrefs = http_get_text(OLD_RELEASES_LINUX_POOL, timeout=300)
        cands = sorted(set(FLOOR_KERNEL_RE.findall(hrefs)))
        if not cands:
            raise SystemExit("no linux-image-unsigned-5.13.0-*-generic amd64 deb in the pool")
        deb_name = cands[-1]
        deb_url = OLD_RELEASES_LINUX_POOL + deb_name
    elif suite in ("lts", "latest"):
        dirs = dists_suite_dirs()
        if suite == "lts":
            lts = []
            for d in dirs:
                if "-" in d or d == DEVEL_ALIAS:
                    continue
                meta = suite_meta(d)
                if not meta or not LTS_VERSION_RE.match(meta["version"]):
                    continue
                if int(LTS_VERSION_RE.match(meta["version"]).group(1)) % 2 != 0:
                    continue
                key = version_key(meta["version"])
                if key:
                    lts.append((key, d))
            if not lts:
                raise SystemExit(
                    "no released Ubuntu LTS suite found (Version YY.04 with an even YY)"
                )
            lts.sort()
            lts_dir = lts[-1][1]
            say(f"lts lane: {lts_dir} (Ubuntu {suite_meta(lts_dir)['version']} LTS)")
            best = resolve_kernel(lts_dir)
            if best is None:
                raise SystemExit(f"no generic unsigned kernel resolved for {lts_dir}")
        else:
            say("resolving the archive's latest kernel (two newest suites)...")
            dated = []
            for d in dirs:
                if "-" in d:
                    continue  # pockets ride along inside resolve_kernel
                meta = suite_meta(d)
                if meta:
                    dated.append((meta["date"], d))
            dated.sort(key=lambda x: x[0], reverse=True)
            newest = []
            for _, d in dated:
                if d not in newest:
                    newest.append(d)
                if len(newest) == 2:
                    break
            if not newest:
                raise SystemExit("no suite Release carried Date+Version — archive restructure?")
            say(f"newest suites: {', '.join(newest)}")
            best = None
            for d in newest:
                cand = resolve_kernel(d)
                if cand is not None and (best is None or cand[0] > best[0]):
                    best = cand
            if best is None:
                raise SystemExit("no generic unsigned kernel resolved across the newest suites")
        deb_url = ARCHIVE_POOL + best[1]
    else:
        raise SystemExit(f"unknown suite: {suite} (floor|lts|latest)")
    return _kernel_from_deb(deb_url, cache, out)


def _kernel_from_deb(deb_url, cache, out):
    say(f"downloading {os.path.basename(deb_url)}...")
    deb_path = os.path.join(cache, os.path.basename(deb_url))
    download_atomic(deb_url, deb_path, timeout=900)
    with open(deb_path, "rb") as fh:
        data = deb_data_tar(fh.read())
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        member = next(
            (
                m
                for m in tar.getmembers()
                if m.name.startswith("./boot/vmlinuz-") or m.name.startswith("boot/vmlinuz-")
            ),
            None,
        )
        if member is None:
            raise SystemExit("no vmlinuz inside the kernel deb")
        with open(out, "wb") as fh:
            fh.write(tar.extractfile(member).read())
    os.chmod(out, 0o644)
    say(f"kernel: {out} ({os.path.getsize(out) // 1024} KiB)")
    return out


# ── initrd assembly ─────────────────────────────────────────────────────────


def ensure_ubuntu_base(cache):
    """The newest 22.04 point release tarball, pinned-name fallback."""
    out = os.path.join(cache, "ubuntu-base.tar.gz")
    if os.path.exists(out):
        return out
    say("resolving the ubuntu:22.04 base tarball...")
    name = UBUNTU_BASE_PINNED
    try:
        hrefs = http_get_text(UBUNTU_BASE_URL, timeout=60)
        cands = sorted(set(re.findall(r"ubuntu-base-22\.04\.[0-9]+-base-amd64\.tar\.gz", hrefs)))
        if cands:
            name = cands[-1]
    except Exception as e:  # noqa: BLE001 - pinned fallback on listing failure
        say(f"listing failed ({e}); falling back to the pinned {name}")
    say(f"downloading {name}...")
    download_atomic(UBUNTU_BASE_URL + name, out, timeout=900)
    say(f"base tarball: {out} ({os.path.getsize(out) // (1024 * 1024)} MiB)")
    return out


def git_archive_into(repo, dest):
    """git archive HEAD (tracked files only, the CI VM contract)
    extracted into dest/."""
    proc = subprocess.run(
        ["git", "-C", repo, "archive", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"git archive HEAD failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace')[:200]}"
        )
    extract_tar_bytes_into(proc.stdout, dest)


def build_initrd(cache, repo, binary, init, payload):
    rootfs = tempfile.mkdtemp(prefix="zelynic-sandbox-rootfs-")
    try:
        # 1. the base userland
        say("extracting the ubuntu:22.04 base...")
        with tarfile.open(ensure_ubuntu_base(cache)) as tar:
            try:
                tar.extractall(rootfs, filter="fully_trusted")
            except TypeError:
                tar.extractall(rootfs)
        # 2. python3 / iproute2 / curl by real dependency resolution
        say("resolving python3/iproute2/curl against the jammy index...")
        pkg_path = os.path.join(cache, "jammy-Packages.gz")
        if not os.path.exists(pkg_path):
            with open(pkg_path, "wb") as fh:
                fh.write(http_get(JAMMY_PACKAGES, timeout=600))
        with open(pkg_path, "rb") as fh:
            index = parse_packages(fh.read())
        debs_dir = os.path.join(cache, "debs")
        os.makedirs(debs_dir, exist_ok=True)
        for name in resolve_closure(index, ROOT_PACKAGES):
            meta = index[name]
            deb_path = os.path.join(debs_dir, f"{name}.deb")
            if not _intact_deb(deb_path):
                say(f"  fetching {name}...")
                download_atomic(f"{ARCHIVE_POOL}{meta['filename']}", deb_path, timeout=600)
            say(f"  {name} {meta['version']}")
            extract_deb_into(deb_path, rootfs)
        # dpkg alternatives do not run in a plain extraction — make the
        # python3 launcher explicit if the debs did not ship it.
        py = os.path.join(rootfs, "usr/bin/python3")
        py310 = os.path.join(rootfs, "usr/bin/python3.10")
        if not os.path.lexists(py) and os.path.exists(py310):
            os.symlink("python3.10", py)
        # 3. the payload, the init, the repo, the binary
        say("overlaying the repo checkout, binary, init, payload...")
        zdir = os.path.join(rootfs, "opt", "zelynic")
        os.makedirs(zdir, exist_ok=True)
        git_archive_into(repo, zdir)
        shutil.copy2(binary, os.path.join(zdir, "zelynic"))
        os.chmod(os.path.join(zdir, "zelynic"), 0o755)
        sbx = os.path.join(zdir, ".sandbox")
        os.makedirs(sbx, exist_ok=True)
        if payload:
            shutil.copy2(payload, os.path.join(sbx, "payload.sh"))
            os.chmod(os.path.join(sbx, "payload.sh"), 0o755)
        shutil.copy2(init, os.path.join(rootfs, "init"))
        os.chmod(os.path.join(rootfs, "init"), 0o755)
        # 4. pack (degraded /dev placeholders are dropped inside; the
        # synthesized device set carries the real nodes)
        out = os.path.join(cache, "initrd.gz")
        say("packing the newc initramfs...")
        pack_initramfs(rootfs, out)
        os.chmod(out, 0o644)
        say(f"initramfs: {out} ({os.path.getsize(out) // (1024 * 1024)} MiB)")
        return out
    finally:
        shutil.rmtree(rootfs, ignore_errors=True)


# ── self-test (rootless, no network assertions) ────────────────────────────


def parse_newc_for_test(data):
    """A minimal newc reader for the self-test round-trip."""
    entries, off = [], 0
    while off < len(data):
        if off % 4:
            # NIGHT-blade-10: the kernel's strict unpacker (6.12+)
            # rejects exactly this — the round-trip parser must too,
            # or a padding regression hides behind tolerant parsing.
            raise ValueError(f"entry at offset {off} is not 4-aligned")
        hdr = data[off : off + 110]
        if hdr[:6] != b"070701":
            raise ValueError("bad magic")
        fields = [int(hdr[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
        mode, filesize = fields[1], fields[6]
        rdevmajor, rdevminor = fields[9], fields[10]
        namesize = fields[11]
        name = data[off + 110 : off + 110 + namesize - 1].decode()
        off += 110 + namesize + ((-(110 + namesize)) % 4)
        filedata = data[off : off + filesize]
        off += filesize + ((-filesize) % 4)
        if name == "TRAILER!!!":
            break
        entries.append((name, mode, filedata, rdevmajor, rdevminor))
    return entries


def self_test():
    """Unit-verify the pure pieces: the ar reader, the dependency
    resolver, the newc writer, and the atomic cache discipline (a
    tree with a file, a dir, a symlink, and a synthesized device
    node parses back with the exact fields). Network reachability is
    NOT asserted — the entrypoint reports it as a preflight note
    instead."""
    failures = 0

    def check(name, ok, detail=""):
        nonlocal failures
        print(f"  {'OK ' if ok else 'X  '}{name}" + (f" — {detail}" if detail else ""))
        if not ok:
            failures += 1

    # ar: a synthetic two-member archive parses back.
    def ar_member(name, data):
        hdr = f"{name.decode():<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{len(data):<10}".encode()
        return hdr + b"`\n" + data + (b"\n" if len(data) % 2 else b"")

    ar = b"!<arch>\n" + ar_member(b"debian-binary", b"2.0\n")
    ar += ar_member(b"data.tar.xz", lzma.compress(b""))
    members = dict(ar_members(ar))
    check("ar reader parses members", set(members) == {"debian-binary", "data.tar.xz"})
    check("ar reader round-trips bytes", members["debian-binary"] == b"2.0\n")

    # cache discipline (NIGHT-harness-1): an interrupted download must
    # never poison the warm cache — bytes land in a .part twin that is
    # renamed into place only on completion, and a cached deb that lost
    # its ar magic is re-fetched instead of trusted.
    with tempfile.TemporaryDirectory() as td:
        empty = os.path.join(td, "empty.deb")
        open(empty, "wb").close()
        valid = os.path.join(td, "valid.deb")
        with open(valid, "wb") as fh:
            fh.write(b"!<arch>\n" + ar_member(b"debian-binary", b"2.0\n"))
        check(
            "ar magic gates the deb cache (empty fails, intact passes)",
            _intact_deb(empty) is False and _intact_deb(valid) is True,
        )
        atomic = os.path.join(td, "atomic.deb")
        download_atomic("data:application/octet-stream,hi", atomic, timeout=5)
        with open(atomic, "rb") as fh:
            landed = fh.read()
        check(
            "downloads land atomically (no .part twin survives)",
            landed == b"hi" and not os.path.exists(atomic + ".part"),
        )

    # resolver: a synthetic index walks a transitive chain and takes
    # the first alternative of every clause.
    index = {
        "root": {"version": "1", "filename": "r.deb", "depends": ["dep1 | dep2, dep1b"]},
        "dep1": {"version": "1", "filename": "d1.deb", "depends": []},
        "dep1b": {"version": "1", "filename": "d1b.deb", "depends": []},
        "dep2": {"version": "1", "filename": "d2.deb", "depends": []},
    }
    check(
        "resolver walks first alternatives only",
        resolve_closure(index, ["root"]) == ["root", "dep1", "dep1b"],
    )
    check("resolver tolerates unknown deps", resolve_closure(index, ["ghost"]) == [])

    # newc: pack entries, parse them back, verify every field.
    buf = io.BytesIO()
    _newc_entry(buf, 1, ".", 0o040755, b"")
    _newc_entry(buf, 2, "dir", 0o040755, b"")
    _newc_entry(buf, 3, "file.txt", 0o100644, b"payload")
    _newc_entry(buf, 4, "link", 0o120777, b"file.txt")
    _newc_entry(buf, 5, "dev/console", 0o020600, b"", 5, 1)
    _newc_trailer(buf)
    try:
        entries = parse_newc_for_test(buf.getvalue())
        by_name = {e[0]: e for e in entries}
        check(
            "newc writer emits the full entry set",
            set(by_name) == {".", "dir", "file.txt", "link", "dev/console"},
        )
        check(
            "newc modes round-trip (dir/file/symlink)",
            by_name["dir"][1] == 0o040755
            and by_name["file.txt"][1] == 0o100644
            and by_name["link"][1] == 0o120777,
        )
        check(
            "newc data round-trips (payload + symlink target)",
            by_name["file.txt"][2] == b"payload" and by_name["link"][2] == b"file.txt",
        )
        check(
            "newc synthesized device carries rdev 5:1",
            by_name["dev/console"][3] == 5 and by_name["dev/console"][4] == 1,
        )
    except ValueError as e:
        check("newc output parses", False, str(e))

    # The tree walker on disk: same discipline through pack_initramfs.
    tree = tempfile.mkdtemp(prefix="zelynic-pack-selftest-")
    try:
        os.makedirs(os.path.join(tree, "dir"))
        os.makedirs(os.path.join(tree, "emptydev"), exist_ok=True)
        # A usr-merge-shaped pair: mergedbin is a symlink TO a
        # directory (NIGHT-blade-10 — os.walk files link-dirs under
        # dirnames; the walker must emit the SYMLINK, never an empty
        # directory, or the image loses its dynamic-linker path).
        os.makedirs(os.path.join(tree, "usrbin"), exist_ok=True)
        with open(os.path.join(tree, "usrbin", "prog"), "w") as fh:
            fh.write("x")
        os.symlink("usrbin", os.path.join(tree, "mergedbin"))
        with open(os.path.join(tree, "file.txt"), "w") as fh:
            fh.write("payload")
        os.symlink("file.txt", os.path.join(tree, "link"))
        out_gz = os.path.join(tree, "test-initrd.gz")
        pack_initramfs(tree, out_gz)
        with gzip.open(out_gz, "rb") as fh:
            entries = parse_newc_for_test(fh.read())
        names = {e[0] for e in entries}
        by_name = {e[0]: e for e in entries}
        dev = {e[0]: e for e in entries if e[0].startswith("dev/")}
        check(
            "symlinked directory rides as a symlink (usr-merge)",
            by_name.get("mergedbin", (None, None, None))[1] == 0o120777
            and by_name["mergedbin"][2] == b"usrbin"
            and "usrbin/prog" in names,
            "an empty dir here deleted /lib64 from real images",
        )
        check(
            "pack_initramfs walks the tree into the archive",
            {"dir", "file.txt", "link"} <= names,
        )
        check(
            "pack_initramfs synthesizes device nodes the tree lacks",
            "dev/console" in dev
            and dev["dev/console"][1] == 0o020600
            and dev["dev/console"][3] == 5
            and dev["dev/console"][4] == 1
            and "dev/null" in dev
            and "dev/tty" in dev
            and "dev/ttyS0" in dev,
            "the emptydev/ tree carries no device nodes at all",
        )
    except ValueError as e:
        check("pack_initramfs output parses", False, str(e))
    finally:
        shutil.rmtree(tree, ignore_errors=True)

    print()
    if failures:
        print(f"self-test: {failures} FAILED")
        return 1
    print("self-test: all green")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="rootfs-pack", description="the zelynic sandbox provisioner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("kernel", help="resolve + fetch a vmlinuz into the cache")
    k.add_argument("--suite", choices=["floor", "lts", "latest"], default="lts")
    k.add_argument("--cache", required=True)
    i = sub.add_parser("initrd", help="build the gzipped newc initramfs")
    i.add_argument("--cache", required=True)
    i.add_argument("--repo", required=True)
    i.add_argument("--binary", required=True)
    i.add_argument("--init", required=True)
    i.add_argument("--payload", default=None)
    sub.add_parser("self-test", help="rootless unit checks, no network")
    args = ap.parse_args()

    if args.cmd == "self-test":
        return self_test()
    os.makedirs(args.cache, exist_ok=True)
    if args.cmd == "kernel":
        print(fetch_kernel(args.suite, args.cache))
        return 0
    build_initrd(args.cache, args.repo, args.binary, args.init, args.payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
