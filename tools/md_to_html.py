#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: md_to_html.py
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Date.......: 2026.05.28
# Version....: 1.1.0
# Purpose....: Minimal Markdown -> HTML converter used as pandoc fallback by
#              the 'make to-html' target. Requires: pip install markdown
# Usage.....: python3 md_to_html.py <input.md> <output.html> [title [css]]
# License...: Apache License Version 2.0
# ------------------------------------------------------------------------------
"""Minimal Markdown to HTML converter (pandoc fallback for make to-html).

Loads docs/report.css when provided as the 4th argument; falls back to a
compact inline stylesheet so the output is always readable standalone.
"""

import sys
from pathlib import Path

import markdown

# Used only when docs/report.css is not passed or not found.
_CSS_FALLBACK = (
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,"
    "sans-serif;font-size:16px;line-height:1.5;color:#24292f;max-width:1100px;"
    "margin:2rem auto;padding:0 2rem}"
    "h1,h2{border-bottom:1px solid #d0d7de;padding-bottom:.3em}"
    "h1{font-size:2em}h2{font-size:1.5em}h3{font-size:1.25em}"
    "a{color:#0969da;text-decoration:none}"
    "table{border-collapse:collapse;width:100%;margin:1em 0;"
    "display:block;overflow-x:auto;font-size:.93em}"
    "td,th{border:1px solid #d0d7de;padding:.375em .75em;text-align:left;"
    "vertical-align:top}"
    "th{background:#f6f8fa;font-weight:600}"
    "tr:nth-child(even){background:#f6f8fa}"
    "code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:85%;"
    "background:#f6f8fa;padding:.2em .4em;border-radius:6px}"
    "pre{background:#f6f8fa;border-radius:6px;padding:1em;overflow-x:auto}"
    "pre code{background:none;padding:0;font-size:100%}"
    "blockquote{margin:0;padding:.2em 1em;color:#57606a;"
    "border-left:.25em solid #d0d7de}"
    "td strong{color:#cf222e}"
    "nav#TOC,#TOC{background:#f6f8fa;border:1px solid #d0d7de;border-radius:6px;"
    "padding:1em 1.5em;margin-bottom:2em;display:inline-block}"
)


def convert(
    src: Path,
    dst: Path,
    title: str,
    css_file: Path | None = None,
) -> None:
    if css_file and css_file.exists():
        css = f"<style>\n{css_file.read_text(encoding='utf-8')}\n</style>"
    else:
        css = f"<style>{_CSS_FALLBACK}</style>"

    body = markdown.markdown(
        src.read_text(encoding="utf-8"),
        extensions=["tables", "fenced_code", "toc"],
        extension_configs={"toc": {"title": "Inhalt"}},
    )
    html = (
        "<!doctype html>\n"
        f'<html lang="de"><head><meta charset="utf-8">\n'
        f"<title>{title}</title>\n"
        f"{css}</head>\n"
        f"<body>{body}</body></html>\n"
    )
    dst.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Usage: md_to_html.py <input.md> <output.html> [title [css]]")
    src_path = Path(sys.argv[1])
    dst_path = Path(sys.argv[2])
    doc_title = sys.argv[3] if len(sys.argv) > 3 else src_path.stem
    css_path = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    convert(src_path, dst_path, doc_title, css_file=css_path)
