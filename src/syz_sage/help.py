"""Readable argparse help, with color applied only at the output boundary."""

from __future__ import annotations

import argparse
import re
import sys
import textwrap
from typing import Any, Protocol, TextIO, cast

from .terminal import safe_text, style, terminal_width

_COMMANDS = "update|show|list|filter|status|check|import-legacy|migrate"
_TOKENS = re.compile(r"(?<![\w-])--?[A-Za-z][A-Za-z0-9-]*")
_COMMAND_ROW = re.compile(rf"^(\s+)({_COMMANDS})(\s{{2,}}.*)$")
_EXAMPLE = re.compile(r"^(\s+)(ss)(\s+.*)$")


class _Writer(Protocol):
    def write(self, text: str, /) -> object: ...


def _style(value: str, *, stream: _Writer, tone: str = "heading") -> str:
    if not callable(getattr(stream, "isatty", None)):
        return value
    return style(value, tone=tone, stream=cast(TextIO, stream))


class HelpFormatter(argparse.HelpFormatter):
    """Wrap prose while keeping examples on separate, indented lines."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if sys.version_info >= (3, 14):
            kwargs["color"] = False
        super().__init__(*args, **kwargs)

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        if "\n" not in text:
            return super()._fill_text(text, width, indent)
        lines = []
        for line in text.splitlines():
            if not line.strip():
                lines.append("")
                continue
            leading = len(line) - len(line.lstrip())
            prefix = indent + " " * leading
            lines.append(
                textwrap.fill(
                    line.strip(),
                    width,
                    initial_indent=prefix,
                    subsequent_indent=prefix + ("  " if leading else ""),
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
        return "\n".join(lines)

    def _format_action(self, action: argparse.Action) -> str:
        if isinstance(action, argparse._SubParsersAction):
            # The usage line already says COMMAND; list command descriptions
            # directly instead of repeating that placeholder above them.
            return "".join(self._format_action(item) for item in action._get_subactions())
        return super()._format_action(action)


class HelpParser(argparse.ArgumentParser):
    """Keep format_help plain; style printing for the actual destination stream."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", HelpFormatter)
        # Python 3.14 has its own help colors; use one consistent implementation
        # across every supported Python version and respect the chosen stream.
        if sys.version_info >= (3, 14):
            kwargs["color"] = False
        self._help_stream: _Writer | None = None
        super().__init__(*args, **kwargs)
        self._positionals.title = "Arguments"
        self._optionals.title = "Options"

    def _get_formatter(self) -> argparse.HelpFormatter:
        width = terminal_width(cast(TextIO | None, self._help_stream))
        return HelpFormatter(
            prog=self.prog,
            width=width,
            max_help_position=min(30, max(12, width // 3)),
        )

    def print_help(self, file: _Writer | None = None) -> None:
        self._print_for_stream(file or sys.stdout, usage_only=False)

    def print_usage(self, file: _Writer | None = None) -> None:
        self._print_for_stream(file or sys.stdout, usage_only=True)

    def _print_for_stream(self, stream: _Writer, *, usage_only: bool) -> None:
        prior_stream = self._help_stream
        self._help_stream = stream
        try:
            message = self.format_usage() if usage_only else self.format_help()
            self._print_message(message, stream)
        finally:
            self._help_stream = prior_stream

    def _print_message(self, message: str | None, file: _Writer | None = None) -> None:
        if not message:
            return
        stream = file or sys.stderr
        if message.startswith(f"{self.prog}: error:"):
            message = safe_text(message.rstrip("\n")) + "\n"
        rendered = []
        for line in message.splitlines(keepends=True):
            if line.rstrip().endswith(":") and not line.startswith(" "):
                rendered.append(_style(line.rstrip("\n"), stream=stream) + "\n")
                continue
            row = _COMMAND_ROW.match(line.rstrip("\n"))
            example = _EXAMPLE.match(line.rstrip("\n"))
            line = _TOKENS.sub(
                lambda match: _style(match.group(), tone="accent", stream=stream), line
            )
            if row:
                line = line.replace(row[2], _style(row[2], tone="accent", stream=stream), 1)
            elif example:
                line = line.replace("ss", _style("ss", tone="strong", stream=stream), 1)
            if line.startswith("usage:"):
                line = _style("usage:", stream=stream) + line[len("usage:") :]
            elif line.startswith(f"{self.prog}: error:"):
                prefix = f"{self.prog}: error:"
                line = _style(prefix, tone="error", stream=stream) + line[len(prefix) :]
            rendered.append(line)
        stream.write("".join(rendered))
