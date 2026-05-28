#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: md_to_html.py
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Date.......: 2026.05.28
# Version....: 1.0.0
# Purpose....: Minimal Markdown -> HTML converter used as pandoc fallback by
#              the 'make to-html' target. Requires: pip install markdown
# Usage.....: python3 md_to_html.py <input.md> <output.html> [title]
# License...: Apache License Version 2.0
# ------------------------------------------------------------------------------
"""Minimal Markdown to HTML converter (pandoc fallback for make to-html)."""

import sys
from pathlib import Path

import markdown

_CSS = (
    "body{font-family:sans-serif;max-width:1100px;margin:2em auto;"
    "padding:0 1em;line-height:1.6}"
    "h1,h2,h3{margin-top:1.4em}"
    "table{border-collapse:collapse;width:100%;margin:1em 0}"
    "td,th{border:1px solid #ccc;padding:.4em .7em;text-align:left}"
    "th{background:#f0f0f0;font-weight:600}"
    "tr:nth-child(even){background:#fafafa}"
    "code{background:#f4f4f4;padding:.1em .3em;border-radius:3px;font-size:.92em}"
    "pre{background:#f4f4f4;padding:1em;overflow-x:auto;border-radius:4px}"
    "pre code{background:none;padding:0}"
    "blockquote{border-left:4px solid #ccc;margin:0;padding:.2em 1em;color:#555}"
    "a{color:#0969da}"
    ".toc{background:#f8f8f8;border:1px solid #ddd;padding:1em 1.5em;"
    "margin-bottom:2em;display:inline-block}"
)


def convert(src: Path, dst: Path, title: str) -> None:
    body = markdown.markdown(
        src.read_text(encoding="utf-8"),
        extensions=["tables", "fenced_code", "toc"],
        extension_configs={"toc": {"title": "Inhalt"}},
    )
    html = (
        "<!doctype html>\n"
        f'<html lang="de"><head><meta charset="utf-8">\n'
        f"<title>{title}</title>\n"
        f"<style>{_CSS}</style></head>\n"
        f"<body>{body}</body></html>\n"
    )
    dst.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Usage: md_to_html.py <input.md> <output.html> [title]")
    src_path = Path(sys.argv[1])
    dst_path = Path(sys.argv[2])
    doc_title = sys.argv[3] if len(sys.argv) > 3 else src_path.stem
    convert(src_path, dst_path, doc_title)
