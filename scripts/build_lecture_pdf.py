from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SOURCE_MD = DOCS / "secure_email_code_lecture.md"
OUTPUT_TEX = DOCS / "secure_email_code_lecture.tex"


SPECIAL_CHARS = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def escape_latex(text: str) -> str:
    return "".join(SPECIAL_CHARS.get(char, char) for char in text)


def render_inline(text: str) -> str:
    parts = re.split(r"(`[^`]+`)", text)
    rendered: list[str] = []
    for part in parts:
        if not part:
            continue
        if part.startswith("`") and part.endswith("`"):
            code = part[1:-1].replace("{", r"\{").replace("}", r"\}")
            rendered.append(r"\nolinkurl{" + code + "}")
        else:
            rendered.append(escape_latex(part))
    return "".join(rendered)


def strip_heading_number(title: str) -> str:
    clean = re.sub(r"^\d+(?:\.\d+)*\.\s*", "", title.strip())
    return clean.replace("`", "")


def render_heading(command: str, title: str) -> str:
    return f"\\{command}{{{escape_latex(strip_heading_number(title))}}}"


def flush_paragraph(paragraph: list[str], output: list[str]) -> None:
    if not paragraph:
        return
    text = " ".join(item.strip() for item in paragraph if item.strip())
    if text:
        output.append(render_inline(text))
    paragraph.clear()


def close_list(list_type: str | None, output: list[str]) -> None:
    if list_type == "itemize":
        output.append(r"\end{itemize}")
    elif list_type == "enumerate":
        output.append(r"\end{enumerate}")


def markdown_to_latex(markdown: str) -> tuple[str, str]:
    lines = markdown.splitlines()
    title = "Secure Email Code Lecture"
    if lines and lines[0].startswith("# "):
        title = lines[0][2:].strip()
        lines = lines[1:]

    output: list[str] = []
    paragraph: list[str] = []
    list_type: str | None = None

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            flush_paragraph(paragraph, output)
            close_list(list_type, output)
            list_type = None
            output.append("")
            continue

        if stripped.startswith("### "):
            flush_paragraph(paragraph, output)
            close_list(list_type, output)
            list_type = None
            output.append(render_heading("subsection", stripped[4:]))
            continue

        if stripped.startswith("## "):
            flush_paragraph(paragraph, output)
            close_list(list_type, output)
            list_type = None
            output.append(render_heading("section", stripped[3:]))
            continue

        if stripped.startswith("# "):
            flush_paragraph(paragraph, output)
            close_list(list_type, output)
            list_type = None
            output.append(render_heading("section", stripped[2:]))
            continue

        bullet_match = re.match(r"^-\s+(.*)$", stripped)
        if bullet_match:
            flush_paragraph(paragraph, output)
            if list_type != "itemize":
                close_list(list_type, output)
                output.append(r"\begin{itemize}")
                list_type = "itemize"
            output.append(r"\item " + render_inline(bullet_match.group(1)))
            continue

        number_match = re.match(r"^\d+\.\s+(.*)$", stripped)
        if number_match:
            flush_paragraph(paragraph, output)
            if list_type != "enumerate":
                close_list(list_type, output)
                output.append(r"\begin{enumerate}")
                list_type = "enumerate"
            output.append(r"\item " + render_inline(number_match.group(1)))
            continue

        if list_type is not None:
            close_list(list_type, output)
            list_type = None

        paragraph.append(stripped)

    flush_paragraph(paragraph, output)
    close_list(list_type, output)

    body = "\n".join(output).strip() + "\n"
    return title, body


def build_tex(markdown_path: Path, tex_path: Path) -> None:
    title, body = markdown_to_latex(markdown_path.read_text(encoding="utf-8"))
    document = rf"""\documentclass[11pt,a4paper]{{article}}
\usepackage[a4paper,margin=1in]{{geometry}}
\usepackage[T1]{{fontenc}}
\usepackage[hidelinks]{{hyperref}}
\setlength{{\parindent}}{{0pt}}
\setlength{{\parskip}}{{0.6em}}
\emergencystretch=2em
\hypersetup{{
  pdftitle={{{escape_latex(title)}}},
  pdfauthor={{OpenAI Codex}},
  pdfsubject={{Educational lecture notes for the smart secure email implementation}}
}}
\title{{{escape_latex(title)}}}
\author{{Secure Email Project}}
\date{{\today}}
\begin{{document}}
\maketitle
\tableofcontents
\newpage
{body}
\end{{document}}
"""
    tex_path.write_text(document, encoding="utf-8")


def compile_pdf(tex_path: Path) -> None:
    for _ in range(2):
        result = subprocess.run(
            [
                "pdflatex",
                "-interaction=nonstopmode",
                "-halt-on-error",
                "-output-directory",
                str(tex_path.parent),
                str(tex_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise SystemExit(result.returncode)


def main() -> None:
    build_tex(SOURCE_MD, OUTPUT_TEX)
    if "--tex-only" not in sys.argv:
        compile_pdf(OUTPUT_TEX)


if __name__ == "__main__":
    main()
