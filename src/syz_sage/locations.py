"""Source locations and stack frames extracted from retained crash reports.

Locations refer to the reported kernel build. Inferred locations retain their
method and evidence and must not be treated as verified source coordinates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

RUNTIME_PREFIXES = (
    "kasan_",
    "__kasan",
    "kmsan_",
    "__kmsan",
    "ubsan_",
    "__ubsan",
    "__asan",
    "asan_",
    "kfence_",
    "__kfence",
    "kcsan_",
    "__kcsan",
    "dump_stack",
    "panic",
    "report_bug",
    "handle_bug",
    "exc_",
    "asm_exc_",
    "warn_slowpath",
    "__warn",
    "lockdep_",
    "check_",
    "print_",
    "show_",
    "die",
    "oops_",
    "instrument_",
    "__sanitizer",
    "arch_static_branch",
    "trace_",
)


@dataclass
class Frame:
    function: str
    path: str
    line: int
    raw: str
    column: int | None = None


@dataclass
class CrashSite:
    function: str = ""
    path: str = ""
    line: int | None = None
    strategy: str = "unresolved"
    confidence: str = "low"
    secondary_function: str = ""
    secondary_path: str = ""
    secondary_line: int | None = None
    evidence: str = ""
    frames: list[Frame] = field(default_factory=list)
    column: int | None = None


def clean_function(value: str) -> str:
    value = value.strip()
    value = re.sub(r"\.(?:constprop|isra|part)\.\d+$", "", value)
    value = re.sub(r"\.(?:cold|llvm)\.\d+$", "", value)
    value = re.sub(r"\.(?:cold|hot)$", "", value)
    return value


def normalize_path(value: str) -> str:
    value = value.strip()
    while value.startswith("./"):
        value = value[2:]
    return value


PATH_LINE_RE = re.compile(
    r"(?P<path>(?:[A-Za-z0-9_.+~-]+/)+[A-Za-z0-9_.+~-]+\.(?:c|h|S|s|rs))"
    r":(?P<line>\d+)(?::(?P<column>\d+))?"
)
_KCSAN_ACCESS_RE = re.compile(
    r"^\s*(?:\[[^]]+\]\s*)?(?:read|write|read-write)(?:\s+\([^)]+\))?"
    r"\s+to .+\bby (?:task|interrupt)\b[^\n]*:\s*$",
    re.I | re.M,
)


def function_from_frame_line(line: str, path_start: int) -> str:
    # A warning can contain an explicit diagnostic coordinate followed by a
    # different symbol+coordinate. Bind only the symbol immediately preceding
    # this path; never borrow a symbol from later on the line.
    previous = [match for match in PATH_LINE_RE.finditer(line[:path_start])]
    prefix = line[previous[-1].end() if previous else 0 : path_start]
    prefix = re.sub(r"\[[^]]*\]", " ", prefix)
    match = re.search(
        r"\b([A-Za-z_][\w.]*)(?:\+0x[0-9a-fA-F]+(?:/0x[0-9a-fA-F]+)?)?\s*$",
        prefix,
    )
    ignored = {"RIP", "CPU", "BUG", "WARNING", "at", "in", "inline", "TASK", "from"}
    return clean_function(match[1]) if match and match[1] not in ignored else ""


def parse_frames(text: str) -> list[Frame]:
    frames: list[Frame] = []
    for raw in text.splitlines():
        # Detector headlines carry a source location but are not stack frames;
        # treating words such as "bounds" as a function corrupts S and CS.
        if (
            re.match(r"^\s*(?:BUG:\s*)?(?:UBSAN|KASAN|KMSAN|KCSAN|KFENCE):", raw)
            and "+0x" not in raw
        ):
            continue
        matched_path = False
        for match in PATH_LINE_RE.finditer(raw):
            matched_path = True
            func = function_from_frame_line(raw, match.start())
            if not func:
                continue
            frame = Frame(
                func,
                normalize_path(match.group("path")),
                int(match.group("line")),
                raw.strip(),
                int(match["column"]) if match["column"] else None,
            )
            if not frames or (frame.function, frame.path, frame.line) != (
                frames[-1].function,
                frames[-1].path,
                frames[-1].line,
            ):
                frames.append(frame)
        # Architecture symbolization occasionally omits file:line for one
        # application frame while retaining the function+offset.  Keep such a
        # frame for S, but do not use it as a standalone CS location.
        if not matched_path and (
            raw[:1].isspace() or raw.lstrip().startswith(("RIP:", "pc :", "lr :"))
        ):
            funcs = re.findall(r"\b([A-Za-z_][A-Za-z0-9_.]*)\+0x[0-9a-fA-F]+", raw)
            if funcs:
                func = clean_function(funcs[-1])
                frame = Frame(func, "", 0, raw.strip())
                if not frames or frame.function != frames[-1].function:
                    frames.append(frame)
    return frames


_AUXILIARY_HEADINGS = (
    ("allocation", re.compile(r"Allocated by task|Page(?: last)? allocated via order", re.I)),
    ("free", re.compile(r"Freed by task|Page last free stack trace", re.I)),
    ("origin", re.compile(r"Uninit was (?:created|stored)\b|Origin:|Local variable", re.I)),
)
_MEMORY_HEADING = re.compile(
    r"The buggy address (?:belongs|is located)|Memory state around|page_owner tracks the page",
    re.I,
)


def _auxiliary_section(line: str) -> str | None:
    for section, pattern in _AUXILIARY_HEADINGS:
        if pattern.search(line):
            return section
    return None


def split_manifestation_report(report: str) -> tuple[str, str, str]:
    """Keep origin and allocation history out of the failing access's frames."""
    boundaries: list[tuple[int, int, str | None]] = []
    offset = 0
    for line in report.splitlines(keepends=True):
        section = _auxiliary_section(line)
        if section or _MEMORY_HEADING.search(line):
            boundaries.append((offset, offset + len(line), section))
        offset += len(line)
    main = report[: boundaries[0][0]] if boundaries else report
    sections: dict[str, str] = {}
    for index, (_, start, section) in enumerate(boundaries):
        if section is not None and section in {"free", "allocation"} and section not in sections:
            end = boundaries[index + 1][0] if index + 1 < len(boundaries) else len(report)
            sections[section] = report[start:end]
    return main, sections.get("free", ""), sections.get("allocation", "")


def title_functions(title: str) -> list[str]:
    title = re.sub(r"\s+\(\d+\)$", "", title.strip())
    race = re.search(r"data-race in ([A-Za-z_][\w.]*)\s*/\s*([A-Za-z_][\w.]*)", title)
    if race:
        return [clean_function(race.group(1)), clean_function(race.group(2))]
    out = re.findall(r"\b(?:in|at)\s+([A-Za-z_][A-Za-z0-9_.]*)(?![\w./])", title)
    return [clean_function(x) for x in out]


def is_runtime_function(func: str) -> bool:
    return (
        not func
        or func.startswith(RUNTIME_PREFIXES)
        or func
        in {
            "__dump_stack",
            "dump_stack_lvl",
            "do_error_trap",
            "do_trap",
            "__die_body",
            "make_task_dead",
            "__might_resched",
            "lock_acquire",
            "lock_release",
            "__lock_acquire",
            "kmem_cache_alloc",
            "kfree",
            "__kmalloc",
            "__slab_free",
            "slab_free_freelist_hook",
        }
    )


def locate_kcsan_sites(title: str, report: str) -> list[CrashSite]:
    """Keep two access stacks distinct, even when their grouping symbols match.

    A labeled KCSAN access starts at the first frame of its stack, including
    an inline or unsymbolized frame. A caller cannot supply missing access
    coordinates. Without section boundaries, repeated grouping symbols do
    not establish which occurrence belongs to which access.
    """
    targets = title_functions(title)[:2]
    main = split_manifestation_report(report)[0]
    headings = list(_KCSAN_ACCESS_RE.finditer(main))
    sites: list[CrashSite] = []
    if headings:
        for index, heading in enumerate(headings[:2]):
            end = headings[index + 1].start() if index + 1 < len(headings) else len(main)
            frames = extract_stack_frames(main[heading.end() : end])
            frame = frames[0] if frames else None
            sites.append(
                CrashSite(
                    function=frame.function or "" if frame else "",
                    path=frame.file_path or "" if frame else "",
                    line=frame.line_number if frame else None,
                    column=frame.column_number if frame else None,
                    strategy="KCSAN labeled access stack"
                    if frame and frame.file_path
                    else "function only; access source unresolved",
                    confidence="medium" if frame and frame.file_path else "low",
                    evidence=frame.raw_line if frame else heading.group().strip(),
                )
            )
        while len(sites) < 2:
            sites.append(
                CrashSite(strategy="conflicting access not present in report", evidence=title)
            )
        return sites

    frames_without_sections = parse_frames(main)
    for target in targets:
        titled_frame = (
            next((frame for frame in frames_without_sections if frame.function == target), None)
            if len(set(targets)) == len(targets)
            else None
        )
        sites.append(
            CrashSite(
                function=target,
                path=titled_frame.path if titled_frame else "",
                line=titled_frame.line or None if titled_frame else None,
                column=titled_frame.column if titled_frame else None,
                strategy="KCSAN distinct title function matched to stack"
                if titled_frame and titled_frame.path
                else "function only; access unresolved",
                confidence="medium" if titled_frame and titled_frame.path else "low",
                evidence=titled_frame.raw if titled_frame else title,
            )
        )
    return sites


def locate_crash_site(title: str, report: str) -> CrashSite:
    main, _, _ = split_manifestation_report(report)
    frames = parse_frames(main)
    targets = title_functions(title)

    # UBSAN supplies the true expression location directly, before its runtime stack.
    for raw in main.splitlines()[:80]:
        if "UBSAN:" in raw or "runtime error:" in raw:
            loc = PATH_LINE_RE.search(raw)
            if loc:
                path, line = normalize_path(loc.group("path")), int(loc.group("line"))
                matching = next(
                    (f for f in frames if f.path == path and f.line == line),
                    None,
                )
                func = matching.function if matching else ""
                return CrashSite(
                    function=func,
                    path=path,
                    line=line,
                    strategy="sanitizer explicit source location",
                    confidence="high",
                    evidence=raw.strip()[:500],
                    frames=frames,
                    column=int(loc["column"]) if loc["column"] else None,
                )

    # Sanitizer headlines can name an inlined access inside the function used
    # for syzbot's grouping title. Prefer that explicit access coordinate.
    for raw in main.splitlines()[:80]:
        if re.search(r"(?:KASAN|KMSAN|KFENCE):", raw):
            loc = PATH_LINE_RE.search(raw)
            functions = title_functions(raw)
            if loc and functions:
                return CrashSite(
                    function=functions[0],
                    path=normalize_path(loc.group("path")),
                    line=int(loc.group("line")),
                    strategy="sanitizer explicit access location",
                    confidence="high",
                    evidence=raw.strip()[:500],
                    frames=frames,
                    column=int(loc["column"]) if loc["column"] else None,
                )

    # KCSAN has two equally meaningful conflicting access sites.
    if "KCSAN" in (title + report) and len(targets) >= 2:
        primary, secondary = locate_kcsan_sites(title, report)
        primary.secondary_function = secondary.function
        primary.secondary_path = secondary.path
        primary.secondary_line = secondary.line
        primary.frames = frames
        return primary

    # Explicit BUG/WARNING coordinates describe the failing operation, which
    # may be an inline helper inside the function used for the grouping title.
    for raw in main.splitlines()[:120]:
        if "WARNING:" not in raw and "kernel BUG at" not in raw:
            continue
        loc = PATH_LINE_RE.search(raw)
        if loc:
            path, line = normalize_path(loc["path"]), int(loc["line"])
            candidate = next((f for f in frames if f.path == path and f.line == line), None)
            return CrashSite(
                function=candidate.function if candidate else "",
                path=path,
                line=line,
                column=int(loc["column"]) if loc["column"] else None,
                strategy="explicit BUG/WARNING source location",
                confidence="high",
                evidence=raw.strip()[:500],
                frames=frames,
            )

    # For KASAN/KMSAN/KFENCE and lockdep reports, the titled function is the
    # manifestation frame; the RIP commonly points at instrumentation/runtime.
    for target in targets:
        match = next((f for f in frames if f.function == target and f.path), None)
        if match:
            detector = (
                "sanitizer"
                if any(x in (title + report) for x in ("KASAN", "KMSAN", "KFENCE"))
                else "ordinary"
            )
            return CrashSite(
                function=match.function,
                path=match.path,
                line=match.line,
                strategy=f"{detector} title function matched to symbolized stack",
                confidence="high" if detector == "sanitizer" else "medium",
                evidence=match.raw[:500],
                frames=frames,
                column=match.column,
            )

    # RCU diagnostics may contain only a suspicious source location and no
    # backtrace.  Preserve the exact location without inventing a function.
    for raw in main.splitlines()[:80]:
        if "suspicious rcu" in raw.lower() or "suspicious rcu_dereference" in raw.lower():
            loc = PATH_LINE_RE.search(raw)
            if loc:
                return CrashSite(
                    path=normalize_path(loc.group("path")),
                    line=int(loc.group("line")),
                    strategy="explicit RCU diagnostic source location",
                    confidence="high",
                    evidence=raw.strip()[:500],
                    frames=frames,
                    column=int(loc["column"]) if loc["column"] else None,
                )

    # Kernel BUG/WARNING lines often carry the exact source location.
    for raw in main.splitlines()[:120]:
        if any(marker in raw for marker in ("kernel BUG at", "WARNING:", "BUG:")):
            loc = PATH_LINE_RE.search(raw)
            if loc:
                path, line = normalize_path(loc.group("path")), int(loc.group("line"))
                candidate = next((f for f in frames if f.path == path and f.line == line), None)
                func = candidate.function if candidate else ""
                return CrashSite(
                    function=func,
                    path=path,
                    line=line,
                    strategy="explicit BUG/WARNING source location",
                    confidence="high",
                    evidence=raw.strip()[:500],
                    frames=frames,
                    column=int(loc["column"]) if loc["column"] else None,
                )

    # For ordinary oopses, resolve the RIP symbol back to the symbolized frame.
    rip_funcs: list[str] = []
    for raw in main.splitlines():
        if "RIP:" in raw:
            rip_funcs.extend(re.findall(r"\b([A-Za-z_][\w.]*)\+0x", raw))
    for func in rip_funcs:
        func = clean_function(func)
        if is_runtime_function(func):
            continue
        match = next((f for f in frames if f.function == func and f.path), None)
        if match:
            return CrashSite(
                function=match.function,
                path=match.path,
                line=match.line,
                strategy="RIP symbol matched to symbolized stack",
                confidence="high",
                evidence=match.raw[:500],
                frames=frames,
                column=match.column,
            )

    # Do not turn a caller's source location into the known failing function's
    # location when that function has an unsymbolized frame.
    for target in targets:
        match = next((f for f in frames if f.function == target and not f.path), None)
        if match:
            return CrashSite(
                function=target,
                strategy="function only; no manifestation source line",
                evidence=match.raw,
                frames=frames,
            )
    fallback = next((f for f in frames if f.path and not is_runtime_function(f.function)), None)
    if fallback:
        return CrashSite(
            function=fallback.function,
            path=fallback.path,
            line=fallback.line,
            strategy="first non-runtime manifestation frame",
            confidence="low",
            evidence=fallback.raw[:500],
            frames=frames,
            column=fallback.column,
        )
    # A title or unsymbolized frame can identify a function without supplying
    # a source line. Allocation/free traces cannot establish the crash line.
    for target in targets:
        match = next((f for f in frames if f.function == target), None)
        return CrashSite(
            function=target,
            strategy="function only; no manifestation source line",
            evidence=match.raw if match else title,
            frames=frames,
        )
    return CrashSite(frames=frames)


@dataclass(frozen=True)
class StackFrame:
    section: str
    report_line: int
    function: str | None
    file_path: str | None
    line_number: int | None
    column_number: int | None
    is_inline: bool
    raw_line: str


def extract_stack_frames(report: str) -> list[StackFrame]:
    """Retain ordered frames, including inline, origin and unsymbolized frames.

    Raw lines preserve offsets, addresses and other text that is not normalized.
    The original report remains authoritative for unusual stack formats.
    """
    frames: list[StackFrame] = []
    section = "manifestation"
    for number, raw in enumerate(report.splitlines(), 1):
        auxiliary = _auxiliary_section(raw)
        if auxiliary:
            section = auxiliary
        elif _KCSAN_ACCESS_RE.match(raw):
            section = "conflicting-access"
        elif re.search(r"(?:stack backtrace|backtrace) of (?:CPU|task)", raw, re.I):
            section = "other-task"
        elif "unwind stack type:" in raw:
            section = "unwind"
        matches = list(PATH_LINE_RE.finditer(raw))
        symbols = re.findall(r"\b([A-Za-z_][\w.]*)\+0x[0-9a-fA-F]+", raw)
        if matches:
            if re.match(r"^\s*(?:BUG:\s*)?(?:UBSAN|KASAN|KMSAN|KCSAN|KFENCE):", raw):
                continue
            for match in matches:
                function = function_from_frame_line(raw, match.start())
                if not function:
                    continue
                frames.append(
                    StackFrame(
                        section,
                        number,
                        function,
                        normalize_path(match.group("path")),
                        int(match.group("line")) or None,
                        int(match.group("column")) if match.group("column") else None,
                        "[inline]" in raw,
                        raw,
                    )
                )
        elif symbols and (
            raw[:1].isspace()
            or re.match(r"^(?:\[[^]]+\]\s*)?(?:RIP:|pc\s*:|lr\s*:)", raw)
            or re.match(r"^[0-9a-fA-F]{8,16}:\s+[0-9a-fA-F]+\s+\(", raw)
            or re.match(r"^[A-Za-z_][\w.]*\+0x", raw)
        ):
            frames.append(
                StackFrame(
                    section,
                    number,
                    clean_function(symbols[-1]),
                    None,
                    None,
                    None,
                    False,
                    raw,
                )
            )
        elif re.fullmatch(r"\s*(?:\[[^]]+\]\s*)?\[<[0-9a-fA-F]+>\](?:\s+.*)?", raw):
            frames.append(StackFrame(section, number, None, None, None, None, False, raw))
    return frames
