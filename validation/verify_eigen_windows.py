"""Fork-only exact-source Windows evidence. Never include in the product PR."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = Path.cwd()
OUT = ROOT / "evidence"
OUT.mkdir(exist_ok=True)
LOCK = json.loads((HERE / "windows-lock.json").read_text())
MUTEX = threading.Lock()
REPORT = {"platform": platform.platform(), "python": sys.version,
          "lock_sha256": hashlib.sha256((HERE / "windows-lock.json").read_bytes()).hexdigest(),
          "commands": [], "failures": [], "dependencies": {}, "cases": [],
          "source_hashes": {}, "archive_hashes": {}, "header_hashes": {}, "native_libraries": {}}


def save():
    with MUTEX:
        (OUT / "report.json").write_text(json.dumps(REPORT, indent=2) + "\n")


def check(condition, message):
    if not condition:
        REPORT["failures"].append(message)
    save()


def run(name, args, cwd=ROOT, env=None, timeout=300):
    args = list(map(str, args))
    log = OUT / (name.replace("/", "-") + ".log")
    start = time.monotonic()
    with log.open("wb") as stream:
        try:
            result = subprocess.run(args, cwd=cwd, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout, check=False)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = "timeout"
        except OSError as error:
            stream.write((type(error).__name__ + ": " + str(error) + "\n").encode())
            code = "spawn_error"
    item = {"name": name, "args": args, "cwd": str(cwd), "returncode": code,
            "seconds": time.monotonic() - start, "log": log.name}
    with MUTEX:
        REPORT["commands"].append(item)
    save()
    print(json.dumps(item), flush=True)
    return item, log.read_text(errors="replace")


def require(result):
    if result["returncode"] != 0:
        raise RuntimeError(result["name"] + " failed; see " + result["log"])


def checkout(name, url, sha):
    dest = ROOT / "inputs" / name
    dest.mkdir(parents=True, exist_ok=True)
    for suffix, args in (("init", ["git", "init", "-q", dest]),
                         ("fetch", ["git", "-C", dest, "fetch", "--depth", "1", url, sha]),
                         ("checkout", ["git", "-C", dest, "-c", "core.autocrlf=false", "-c", "core.longpaths=true", "checkout", "--detach", "FETCH_HEAD"])):
        result, _ = run(name + "-" + suffix, args, timeout=180)
        require(result)
    actual = subprocess.check_output(["git", "-C", str(dest), "rev-parse", "HEAD"]).decode().strip()
    if actual != sha:
        raise RuntimeError("Wrong dependency revision: " + name)
    with MUTEX:
        REPORT["dependencies"][name] = {"url": url, "expected": sha, "actual": actual}
    save()
    return dest


def unpack(name, spec, include_only=False):
    archive = ROOT / "archives" / spec["filename"]
    archive.parent.mkdir(exist_ok=True)
    result, _ = run("download-" + name, ["curl.exe", "-4", "-L", "--fail", "--silent", "--show-error",
                       "--connect-timeout", "15", "--max-time", "120", spec["url"], "-o", archive], timeout=125)
    require(result)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != spec["sha256"]:
        raise RuntimeError("Archive hash mismatch: " + name)
    REPORT["archive_hashes"][name] = digest
    dest = ROOT / "inputs" / name
    dest.mkdir(parents=True)
    with tarfile.open(archive, "r:*") as source:
        members = source.getmembers()
        if include_only:
            prefix = spec["include_prefix"].rstrip("/") + "/"
            members = [m for m in members if m.name.startswith(prefix) and
                       (m.name[len(prefix):].startswith(("Eigen/", "unsupported/Eigen/")) or
                        m.name[len(prefix):] in ("Eigen", "unsupported/Eigen", "signature_of_eigen3_matrix_library"))]
        source.extractall(dest, members=members, filter="data")
    save()
    return dest / spec.get("include_prefix", "")


def expected_missing_member(result, output):
    return (isinstance(result["returncode"], int) and result["returncode"] != 0
            and "max_digits10" in output
            and re.search(r"not a member|no member named|error C2039", output, re.I) is not None
            and re.search(r"cannot open include|No such file or directory|undefined reference|unresolved external", output, re.I) is None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", choices=["msvc", "mingw"], required=True)
    parser.add_argument("--compiler-path")
    args = parser.parse_args()
    if sys.platform != "win32":
        raise RuntimeError("Requires native Windows; local syntax preflight is separate")
    REPORT["lane"] = args.compiler
    compiler = args.compiler_path or shutil.which("cl")
    if not compiler or not Path(compiler).exists():
        raise RuntimeError("Compiler executable unavailable")
    if args.compiler == "msvc":
        # cl without a source returns nonzero after printing its observed version.
        run("compiler-version", [compiler], timeout=30)
        modes, backends = [14, 17], ["default"]
    else:
        compiler = str(Path(compiler).resolve())
        result, _ = run("compiler-version", [compiler, "--version"], timeout=30)
        require(result)
        result, target = run("compiler-target", [compiler, "-dumpmachine"], timeout=30)
        require(result)
        if "w64-mingw32" not in target:
            raise RuntimeError("Optional lane is not a native MinGW compiler")
        modes, backends = [17], ["default", "GMP", "MPFR", "MPC"]
    REPORT["matrix"] = {"standards": modes, "backends": backends, "eigen": ["3.4.0", "5.0.1"]}
    checkout("boost", LOCK["boost"]["url"], LOCK["boost"]["sha"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(checkout, "boost/" + d["path"], d["url"], d["sha"]) for d in LOCK["boost_dependencies"]]
        for future in concurrent.futures.as_completed(futures):
            future.result()
    sources = {name: checkout(name, LOCK["multiprecision"]["url"], LOCK["multiprecision"][name])
               for name in ("base", "fix")}
    for label, source in sources.items():
        hashes = {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                  for name in LOCK["sources"][label]}
        for name, digest in hashes.items():
            if digest not in LOCK["sources"][label][name].values():
                raise RuntimeError(label + " source hash mismatch: " + name)
        REPORT["source_hashes"][label] = hashes
    regression = sources["fix"] / "test/test_eigen_numtraits.cpp"
    REPORT["regression_sha256"] = hashlib.sha256(regression.read_bytes()).hexdigest()
    REPORT["probe_sha256"] = hashlib.sha256((HERE / "eigen_matrix_probe.cpp").read_bytes()).hexdigest()
    if REPORT["probe_sha256"] not in LOCK["probe_sha256"].values():
        raise RuntimeError("Matrix control source hash mismatch")
    includes = [ROOT / "inputs/boost" / d["path"] / "include"
                for d in LOCK["boost_dependencies"] if d["path"].startswith("libs/")]
    includes.append(ROOT / "inputs/boost")
    eigen = {version: unpack("eigen-" + version, spec, include_only=True)
             for version, spec in LOCK["eigen"].items()}
    for version, path in eigen.items():
        REPORT["header_hashes"][version] = {str(p.relative_to(path)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
                                            for p in path.rglob("*") if p.is_file()}
        digest = hashlib.sha256()
        for name, sha in sorted(REPORT["header_hashes"][version].items()):
            digest.update((name + "\0" + sha + "\n").encode())
        spec = LOCK["eigen"][version]
        if (len(REPORT["header_hashes"][version]) != spec["header_file_count"] or
                digest.hexdigest() != spec["header_tree_sha256"]):
            raise RuntimeError("Eigen header-tree mismatch: " + version)
    env = os.environ.copy()
    native_root = None
    if args.compiler == "mingw":
        for name, spec in LOCK["native_packages"].items():
            unpack("native-" + name, spec)
        native_root = ROOT / "native-libs"
        native_root.mkdir()
        for name in LOCK["native_packages"]:
            extracted = ROOT / "inputs" / ("native-" + name) / "mingw64"
            shutil.copytree(extracted, native_root, dirs_exist_ok=True)
        for name, expected in LOCK["native_files"].items():
            actual = hashlib.sha256((native_root / name).read_bytes()).hexdigest()
            if actual != expected:
                raise RuntimeError("Optional native library identity mismatch: " + name)
            REPORT["native_libraries"][name] = actual
        env["PATH"] = str(native_root / "bin") + os.pathsep + str(Path(compiler).parent) + os.pathsep + env.get("PATH", "")
    binaries = ROOT / "binaries"
    binaries.mkdir()

    def compile_case(name, src, header_source, epath, standard, backend):
        exe = binaries / (name + ".exe")
        incs = [header_source / "include", epath, *includes]
        macro = [] if backend == "default" else ["TEST_" + backend]
        if args.compiler == "msvc":
            command = [compiler, "/nologo", "/EHsc", "/O2", "/W4", "/std:c++" + str(standard),
                       "/Zc:__cplusplus", "/D_CRT_SECURE_NO_WARNINGS", *["/D" + m for m in macro],
                       *["/I" + str(p) for p in incs], src, "/Fe:" + str(exe), "/Fo:" + str(binaries / (name + ".obj"))]
        else:
            command = [compiler, "-std=c++" + str(standard), "-O2", "-Wall", "-Wextra",
                       *["-D" + m for m in macro], *["-I" + str(p) for p in incs]]
            if native_root:
                command += ["-I" + str(native_root / "include")]
            command += [src, "-o", exe]
            if backend != "default":
                command += ["-L" + str(native_root / "lib")]
                command += {"GMP": ["-lgmp"], "MPFR": ["-lmpfr", "-lgmp"],
                            "MPC": ["-lmpc", "-lmpfr", "-lgmp"]}[backend]
        result, output = run(name + "-compile", command, env=env)
        return result, output, exe

    for version, epath in eigen.items():
        for standard in modes:
            for backend in backends:
                key = version + "-cxx" + str(standard) + "-" + backend
                result, output, _ = compile_case(key + "-old-regression", regression, sources["base"], epath, standard, backend)
                old_ok = expected_missing_member(result, output)
                check(old_ok, key + " did not reproduce missing max_digits10 with unchanged regression")
                result, _, exe = compile_case(key + "-fixed-regression", regression, sources["fix"], epath, standard, backend)
                fixed_compile = result["returncode"] == 0
                check(fixed_compile, key + " fixed regression did not compile")
                fixed_run = None
                if fixed_compile:
                    result, output = run(key + "-fixed-run", [exe], env=env)
                    fixed_run = result["returncode"]
                    check(fixed_run == 0, key + " fixed regression failed")
                result, output, exe = compile_case(key + "-old-matrix", HERE / "eigen_matrix_probe.cpp", sources["base"], epath, standard, backend)
                if version == "3.4.0":
                    check(result["returncode"] == 0, key + " old Eigen3 positive compile control failed")
                    if result["returncode"] == 0:
                        result, _ = run(key + "-old-matrix-run", [exe], env=env)
                        check(result["returncode"] == 0, key + " old Eigen3 positive runtime control failed")
                else:
                    check(expected_missing_member(result, output), key + " old Eigen5 matrix did not fail for max_digits10")
                REPORT["cases"].append({"key": key, "original_regression_expected_failure": old_ok,
                                         "fixed_compile": fixed_compile, "fixed_run": fixed_run,
                                         "same_regression_source": str(regression), "regression_sha256": REPORT["regression_sha256"]})
                save()
    REPORT["finished"] = True
    save()
    return int(bool(REPORT["failures"]))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        REPORT["failures"].append(type(error).__name__ + ": " + str(error))
        save()
        raise
    finally:
        save()
