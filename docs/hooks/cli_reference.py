"""MkDocs hook: render the CLI reference from tgmint's own argparse parser.

docs/cli.md holds a placeholder line. At build time this hook replaces it
with the ``--help`` output of every subcommand, so the CLI reference can't
drift out of date: nothing generated is committed.
"""

from __future__ import annotations

import argparse
import os

PLACEHOLDER = "<!-- tgmint-cli-reference -->"


def _subcommands(parser: argparse.ArgumentParser):
    for action in parser._actions:  # argparse has no public accessor
        if isinstance(action, argparse._SubParsersAction):
            help_by_name = {a.dest: a.help for a in action._choices_actions}
            for name, sub in action.choices.items():
                yield name, help_by_name.get(name) or "", sub


def _render() -> str:
    os.environ["COLUMNS"] = "100"  # stable wrapping for the help text
    from tgmint.cli import _build_parser

    parser = _build_parser()
    parser.prog = "tgmint"
    commands = list(_subcommands(parser))

    out = ["| Command | Summary |", "|---|---|"]
    out += [f"| [`{name}`](#{name}) | {summary} |" for name, summary, _ in commands]
    out += ["", "## Global options", "", "```text", parser.format_help().rstrip(), "```", ""]
    for name, _summary, sub in commands:
        out += [f"## `{name}`", "", "```text", sub.format_help().rstrip(), "```", ""]
        for sub_name, sub_summary, subsub in _subcommands(sub):
            out += [
                f"### `{name} {sub_name}`",
                "",
                sub_summary,
                "",
                "```text",
                subsub.format_help().rstrip(),
                "```",
                "",
            ]
    return "\n".join(out)


def on_page_markdown(markdown, page, config, files):
    if PLACEHOLDER in markdown:
        return markdown.replace(PLACEHOLDER, _render())
    return markdown
