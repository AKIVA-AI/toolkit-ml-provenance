"""Static scan of pickle-based model files for dangerous imports (stdlib only).

Loading a pickle can run arbitrary code: every ``GLOBAL`` / ``STACK_GLOBAL``
opcode imports a callable that ``REDUCE`` may then call. This module never
unpickles anything. It walks the opcode stream with :mod:`pickletools` and
classifies each imported global:

* ``safe``: on an allowlist of globals that PyTorch, NumPy and plain
  containers need to rebuild tensors and arrays;
* ``dangerous``: on a denylist of modules and callables that give code
  execution, file or network access (``os``, ``subprocess``, ``builtins.eval``
  ...), or an import whose name cannot be resolved statically;
* ``unknown``: anything else. It is not proven harmful, but it is not known to
  be safe either; strict gates treat it as a failure.

Formats: raw pickles (including several pickles in one file, as in legacy
``torch.save``), PyTorch zip checkpoints (every ``*.pkl`` member), NumPy
``.npy`` with object dtype and ``.npz`` archives of them. Files that are not
pickles (safetensors, GGUF, ONNX, raw tensor ``.bin``) are skipped.

The global extraction follows the same approach as the ``picklescan`` project;
the tests cross-check the extracted globals against it.
"""

from __future__ import annotations

import ast
import io
import pickletools  # nosec B403 - disassembly only; nothing is unpickled
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

PICKLE_SUFFIXES = {
    ".pkl",
    ".pickle",
    ".pt",
    ".pth",
    ".bin",
    ".ckpt",
    ".joblib",
    ".npy",
    ".npz",
    ".dat",
    ".data",
    ".model",
}
# Suffixes that are always pickles; failing to parse one is an error, not a skip.
_ALWAYS_PICKLE = {".pkl", ".pickle"}

SAFE_GLOBALS: dict[str, set[str]] = {
    "collections": {"OrderedDict", "defaultdict", "deque"},
    "builtins": {
        "set",
        "frozenset",
        "dict",
        "list",
        "tuple",
        "bytearray",
        "bytes",
        "complex",
        "slice",
        "range",
        "int",
        "float",
        "bool",
        "str",
    },
    "__builtin__": {"set", "frozenset", "dict", "list", "tuple", "complex", "slice"},
    "copyreg": {"_reconstructor"},
    "copy_reg": {"_reconstructor"},
    "_codecs": {"encode"},
    "torch": {
        "Size",
        "device",
        "dtype",
        "float16",
        "float32",
        "float64",
        "bfloat16",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint8",
        "bool",
        "LongStorage",
        "FloatStorage",
        "HalfStorage",
        "DoubleStorage",
        "BFloat16Storage",
        "BoolStorage",
        "CharStorage",
        "ShortStorage",
        "IntStorage",
        "ByteStorage",
        "ComplexFloatStorage",
        "ComplexDoubleStorage",
        "QInt8Storage",
        "QInt32Storage",
        "QUInt8Storage",
        "QUInt4x2Storage",
        "QUInt2x4Storage",
    },
    "torch._utils": {
        "_rebuild_tensor",
        "_rebuild_tensor_v2",
        "_rebuild_parameter",
        "_rebuild_parameter_with_state",
        "_rebuild_qtensor",
        "_rebuild_sparse_tensor",
    },
    "torch.nn.parameter": {"Parameter"},
    "numpy": {"dtype", "ndarray"},
    "numpy.core.multiarray": {"_reconstruct", "scalar"},
    "numpy._core.multiarray": {"_reconstruct", "scalar"},
}

# "*" means every name in the module (and its submodules) is dangerous.
DANGEROUS_GLOBALS: dict[str, set[str] | str] = {
    "builtins": {
        "eval",
        "exec",
        "compile",
        "open",
        "getattr",
        "setattr",
        "delattr",
        "__import__",
        "apply",
        "breakpoint",
        "input",
        "globals",
        "locals",
        "vars",
    },
    "__builtin__": {
        "eval",
        "exec",
        "compile",
        "open",
        "getattr",
        "setattr",
        "__import__",
        "apply",
        "execfile",
        "file",
        "input",
    },
    "os": "*",
    "posix": "*",
    "nt": "*",
    "subprocess": "*",
    "sys": "*",
    "socket": "*",
    "ssl": "*",
    "shutil": "*",
    "runpy": "*",
    "pty": "*",
    "commands": "*",
    "ctypes": "*",
    "importlib": "*",
    "pickle": "*",
    "_pickle": "*",
    "marshal": "*",
    "code": "*",
    "codeop": "*",
    "pdb": "*",
    "bdb": "*",
    "timeit": "*",
    "profile": "*",
    "cProfile": "*",
    "trace": "*",
    "pydoc": "*",
    "pkgutil": "*",
    "pip": "*",
    "venv": "*",
    "ensurepip": "*",
    "webbrowser": "*",
    "asyncio": "*",
    "multiprocessing": "*",
    "threading": "*",
    "http": "*",
    "httplib": "*",
    "urllib": "*",
    "urllib2": "*",
    "requests": "*",
    "aiohttp": "*",
    "ftplib": "*",
    "smtplib": "*",
    "telnetlib": "*",
    "tempfile": "*",
    "glob": "*",
    "uuid": "*",
    "types": {"CodeType", "FunctionType"},
    "functools": {"partial", "reduce"},
    "operator": {"attrgetter", "itemgetter", "methodcaller"},
    "_operator": {"attrgetter", "itemgetter", "methodcaller"},
    "io": {"FileIO", "open", "open_code"},
    "_io": {"FileIO", "open", "open_code"},
    "logging": {"FileHandler"},
    "cloudpickle": "*",
    "dill": "*",
    "torch.serialization": {"load", "_load"},
    "torch.hub": "*",
    "numpy.f2py": "*",
    "numpy.testing": "*",
}

_STRING_OPS = {
    "SHORT_BINUNICODE",
    "UNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "STRING",
    "BINSTRING",
    "SHORT_BINSTRING",
}
_PUT_OPS = {"MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"}
_GET_OPS = {"GET", "BINGET", "LONG_BINGET"}
UNKNOWN = "<unknown>"


@dataclass
class PickleFinding:
    path: str
    format: str
    verdict: str  # safe | unknown | dangerous | error
    globals: list[dict[str, str]] = field(default_factory=list)
    error: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "path": self.path,
            "format": self.format,
            "verdict": self.verdict,
            "globals": self.globals,
        }
        if self.error:
            out["error"] = self.error
        return out


def classify(module: str, name: str) -> str:
    """Classify one imported global as ``safe``, ``dangerous`` or ``unknown``."""
    if UNKNOWN in (module, name):
        return "dangerous"
    parts = module.split(".")
    for i in range(len(parts), 0, -1):
        rule = DANGEROUS_GLOBALS.get(".".join(parts[:i]))
        if rule is None:
            continue
        if rule == "*":
            return "dangerous"
        if i == len(parts) and name.split(".")[0] in rule:
            return "dangerous"
    if name in SAFE_GLOBALS.get(module, set()):
        return "safe"
    return "unknown"


class _ScanError(Exception):
    def __init__(self, message: str, found: set[tuple[str, str]]):
        super().__init__(message)
        self.found = found


# Legacy (non-zip) torch.save files start with a pickle of this magic number,
# followed by four more pickles and then raw tensor bytes.
TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C
TORCH_LEGACY_PICKLES = 5


def extract_globals(data: IO[bytes], *, multiple: bool = True) -> set[tuple[str, str]]:
    """Every ``(module, name)`` a pickle stream imports, without unpickling.

    With ``multiple``, keeps reading further pickles while the next byte starts
    one (``PROTO``), as loaders that call ``pickle.load`` repeatedly would. A
    legacy ``torch.save`` file is read as exactly its five pickles, so the raw
    tensor bytes after them are never parsed. Raises :class:`_ScanError` if a
    pickle is malformed, carrying the globals found before the error.
    """
    found: set[tuple[str, str]] = set()
    limit: int | None = None
    count = 0
    while True:
        memo: dict[Any, Any] = {}
        ops: list[tuple[str, Any]] = []
        error = ""
        try:
            for opcode, arg, _pos in pickletools.genops(data):
                ops.append((opcode.name, arg))
        except Exception as exc:  # noqa: BLE001 - any parse failure is reported
            error = f"{type(exc).__name__}: {exc}"
        for n, (op, arg) in enumerate(ops):
            if op == "MEMOIZE" and n > 0:
                memo[len(memo)] = ops[n - 1][1]
            elif op in _PUT_OPS and n > 0:
                memo[arg] = ops[n - 1][1]
            elif op in ("GLOBAL", "INST"):
                module, _, name = str(arg).partition(" ")
                found.add((module, name))
            elif op == "STACK_GLOBAL":
                values: list[str] = []
                for back in range(n - 1, -1, -1):
                    prev_op, prev_arg = ops[back]
                    if prev_op in _PUT_OPS:
                        continue
                    if prev_op in _GET_OPS:
                        value = memo.get(prev_arg)
                        values.append(value if isinstance(value, str) else UNKNOWN)
                    elif prev_op in _STRING_OPS and isinstance(prev_arg, str):
                        values.append(prev_arg)
                    else:
                        values.append(UNKNOWN)
                    if len(values) == 2:
                        break
                while len(values) < 2:
                    values.append(UNKNOWN)
                found.add((values[1], values[0]))
        if error:
            raise _ScanError(error, found)
        count += 1
        if count == 1 and [op for op, _ in ops] == ["PROTO", "LONG1", "STOP"]:
            if ops[1][1] == TORCH_LEGACY_MAGIC:
                limit = TORCH_LEGACY_PICKLES
        if not multiple or not ops or (limit is not None and count >= limit):
            return found
        peek = data.read(1)
        if not peek:
            return found
        data.seek(-1, io.SEEK_CUR)
        if peek != b"\x80":
            return found


def _finding(
    path: str, fmt: str, found: set[tuple[str, str]], error: str = ""
) -> PickleFinding:
    rows = [
        {"module": m, "name": n, "safety": classify(m, n)} for m, n in sorted(found)
    ]
    safeties = {r["safety"] for r in rows}
    if "dangerous" in safeties:
        verdict = "dangerous"
    elif error:
        verdict = "error"
    elif "unknown" in safeties:
        verdict = "unknown"
    else:
        verdict = "safe"
    return PickleFinding(path, fmt, verdict, rows, error)


def _scan_stream(path: str, fmt: str, data: IO[bytes]) -> PickleFinding:
    try:
        found = extract_globals(data)
    except _ScanError as exc:
        return _finding(path, fmt, exc.found, str(exc))
    return _finding(path, fmt, found)


def _npy_pickle_offset(head: bytes) -> int | None:
    """Offset of the pickle payload in an object-dtype ``.npy``, else None."""
    if not head.startswith(b"\x93NUMPY"):
        return None
    major = head[6]
    if major == 1:
        hlen, start = int.from_bytes(head[8:10], "little"), 10
    else:
        hlen, start = int.from_bytes(head[8:12], "little"), 12
    header = head[start : start + hlen].decode("latin-1", errors="replace")
    try:
        meta = ast.literal_eval(header.strip())
    except (ValueError, SyntaxError):
        return None
    if isinstance(meta, dict) and "O" in str(meta.get("descr", "")):
        return start + hlen
    return None


def _merge(path: str, fmt: str, parts: list[PickleFinding]) -> PickleFinding:
    rows: dict[tuple[str, str], dict[str, str]] = {}
    errors = []
    for part in parts:
        for row in part.globals:
            rows[(row["module"], row["name"])] = row
        if part.error:
            errors.append(f"{part.path}: {part.error}")
    return _finding(path, fmt, set(rows), "; ".join(errors))


def scan_file(path: Path, rel: str | None = None) -> PickleFinding | None:
    """Scan one file. Returns None when the file is not pickle-based."""
    name = rel or path.name
    suffix = path.suffix.lower()
    with path.open("rb") as fh:
        head = fh.read(4096)
        if zipfile.is_zipfile(fh):
            fh.seek(0)
            try:
                with zipfile.ZipFile(fh) as zf:
                    members = [
                        m
                        for m in zf.namelist()
                        if m.endswith((".pkl", ".pickle")) or m.endswith(".npy")
                    ]
                    if not members:
                        return None
                    parts = []
                    for member in members:
                        raw = zf.read(member)
                        sub = scan_bytes(raw, f"{name}:{member}")
                        if sub is not None:
                            parts.append(sub)
            except (zipfile.BadZipFile, OSError) as exc:
                return PickleFinding(name, "zip", "error", error=str(exc))
            if not parts:
                return None
            fmt = "pytorch-zip" if suffix in {".pt", ".pth", ".bin", ".ckpt"} else "zip"
            return _merge(name, fmt, parts)
        fh.seek(0)
        offset = _npy_pickle_offset(head)
        if offset is not None:
            fh.seek(offset)
            return _scan_stream(name, "numpy-object", fh)
        if head[:1] == b"\x80" and len(head) > 1 and 0 < head[1] <= 5:
            fh.seek(0)
            return _scan_stream(name, "pickle", fh)
        if suffix in _ALWAYS_PICKLE and head:
            fh.seek(0)
            return _scan_stream(name, "pickle", fh)
    return None


def scan_bytes(data: bytes, name: str) -> PickleFinding | None:
    """Scan an in-memory pickle or ``.npy`` payload (used for archive members)."""
    offset = _npy_pickle_offset(data[:4096])
    if offset is not None:
        return _scan_stream(name, "numpy-object", io.BytesIO(data[offset:]))
    if data.startswith(b"\x93NUMPY"):
        return None
    return _scan_stream(name, "pickle", io.BytesIO(data))


def is_candidate(path: Path) -> bool:
    return path.suffix.lower() in PICKLE_SUFFIXES


def scan_paths(root: Path, rel_paths: list[str]) -> list[PickleFinding]:
    """Scan the candidate files among ``rel_paths`` (relative to ``root``)."""
    findings = []
    for rel in rel_paths:
        p = root / rel
        if is_candidate(p) and p.is_file():
            finding = scan_file(p, rel)
            if finding is not None:
                findings.append(finding)
    return findings


def summarize(findings: list[PickleFinding]) -> dict[str, int]:
    counts = {"pickle_files": len(findings)}
    for verdict in ("safe", "unknown", "dangerous", "error"):
        counts[verdict] = sum(1 for f in findings if f.verdict == verdict)
    return counts


def gate_fails(findings: list[PickleFinding], policy: str) -> bool:
    """``policy``: ``dangerous`` fails on dangerous imports; ``unknown`` also on
    unknown imports and unparseable pickles (allowlist mode)."""
    if policy == "dangerous":
        return any(f.verdict == "dangerous" for f in findings)
    if policy == "unknown":
        return any(f.verdict != "safe" for f in findings)
    raise ValueError(f"unknown pickle policy: {policy}")
