#!/usr/bin/env python3
"""Regenerate shared admonition tokens and per-backend family mappings."""

import argparse
import pathlib
import re
import sys
import urllib.parse


HERE = pathlib.Path(__file__).resolve().parent
API = HERE.parent
ICON_DIR = HERE / "support-icons"
BRAND_CSS = API / "docs" / "manual" / "brand.css"

BEGIN = "/* BEGIN GENERATED (scripts/gen_admonitions.py) — do not hand-edit */"
END = "/* END GENERATED (scripts/gen_admonitions.py) */"
LEGACY_MARKERS = ["/* ---- Admonition", "/* Admonitions"]
FADE_WEIGHT = 0.2
DARK_LINK_WEIGHT = 0.5


def read_brand_value(token):
    pattern = rf"--bn-{re.escape(token)}:\s*([^;]+);"
    match = re.search(pattern, BRAND_CSS.read_text())
    if not match:
        raise ValueError(f"missing token --bn-{token} in {BRAND_CSS}")
    return match.group(1).strip()


def read_brand_color(token, resolving=()):
    if token in resolving:
        chain = " -> ".join([*resolving, token])
        raise ValueError(f"cyclic brand color reference: {chain}")

    value = read_brand_value(token)
    if re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
        return value.upper()

    reference = re.fullmatch(r"var\(--bn-([a-z0-9-]+)\)", value)
    if reference:
        return read_brand_color(reference.group(1), (*resolving, token))

    raise ValueError(f"token --bn-{token} does not resolve to a hex color: {value}")


def fade_toward_white(color, weight=FADE_WEIGHT):
    channels = [int(color[index : index + 2], 16) for index in (1, 3, 5)]
    faded = [round(channel * weight + 255 * (1 - weight)) for channel in channels]
    return "#" + "".join(f"{channel:02X}" for channel in faded)


def data_uri(svg_text):
    return (
        "data:image/svg+xml;charset=utf-8,"
        + urllib.parse.quote(" ".join(svg_text.split()), safe="")
    )


ICONS = {
    family: data_uri((ICON_DIR / f"{name}.svg").read_text())
    for family, name in [
        ("info", "Notification"),
        ("success", "Success"),
        ("warning", "Warning"),
        ("danger", "Danger"),
    ]
}

# Family tints are generated from the canonical brand tokens above this file's
# generated fence. Nested headers remain transparent over the card background.
FAMILIES = {
    "info": {
        "base_token": "info",
        "light_token": "info-light",
        "foreground": "var(--bn-night)",
        "icon": "info",
        "zensical": [
            "note", "info", "abstract", "summary", "tldr", "question",
            "help", "faq", "important", "seealso",
        ],
        "sphinx": ["note", "seealso", "important"],
        "sphinx_alert": "info",
        "doxygen": ["note", "todo", "remark", "see"],
    },
    "success": {
        "base_token": "success",
        "light_token": "success-light",
        "foreground": "var(--bn-night)",
        "icon": "success",
        "zensical": ["tip", "hint", "success", "check", "done"],
        "sphinx": ["hint", "tip"],
        "sphinx_alert": "success",
        "doxygen": [],
    },
    "warning": {
        "base_token": "warning",
        "light_token": "warning-light",
        "foreground": "var(--bn-night)",
        "icon": "warning",
        "zensical": ["warning", "caution", "attention"],
        "sphinx": ["admonition-todo", "attention", "caution", "warning"],
        "sphinx_alert": "warning",
        "doxygen": ["warning", "attention", "deprecated"],
        "rust": True,
    },
    "danger": {
        "base_token": "danger",
        "light_token": "danger-light",
        "foreground": "var(--bn-night)",
        "icon": "danger",
        "zensical": ["danger", "error", "failure", "fail", "missing", "bug"],
        "sphinx": ["danger", "error"],
        "sphinx_alert": "danger",
        "doxygen": ["bug"],
    },
    "example": {
        "base_token": "accent-navy",
        "light_token": "accent-navy-light",
        "foreground": "var(--bn-night)",
        "icon": "info",
        "zensical": ["example", "quote", "cite"],
        "sphinx": [],
        "doxygen": [],
    },
}


def fenced_source(path, generated):
    source = path.read_text()
    block = f"{BEGIN}\n{generated.rstrip()}\n{END}\n"
    begin, end = source.find(BEGIN), source.find(END)
    if begin >= 0 and end > begin:
        source = source[:begin] + block + source[end + len(END) :].lstrip("\n")
    else:
        for marker in LEGACY_MARKERS:
            index = source.find(marker)
            if index >= 0:
                source = source[:index].rstrip() + "\n\n" + block
                break
        else:
            source = source.rstrip() + "\n\n" + block
    return source


def variable_lines(family):
    values = FAMILIES[family]
    return "\n".join(
        [
            f"  --bn-adm-card-bg: var(--bn-adm-{family}-bg);",
            f"  --bn-adm-card-fg: var(--bn-adm-{family}-fg);",
            f"  --bn-adm-card-icon: var(--bn-adm-icon-{values['icon']});",
        ]
    )


icon_lines = "\n".join(
    f'  --bn-adm-icon-{family}: url("{uri}");' for family, uri in ICONS.items()
)
color_lines = "\n".join(
    f"  --bn-adm-{family}-bg: var(--bn-{values['light_token']});\n"
    f"  --bn-adm-{family}-fg: {values['foreground']};"
    for family, values in FAMILIES.items()
)
light_color_lines = "\n".join(
    f"  --bn-{values['light_token']}: "
    f"{fade_toward_white(read_brand_color(values['base_token']))};"
    for values in FAMILIES.values()
)
brand_block = f"""\
:root {{
  /* 20% canonical brand color mixed with 80% white. */
{light_color_lines}
  /* Dark-surface links use a distinct 50% blend of the light link color. */
  --bn-link-dark-blend: {fade_toward_white(read_brand_color("link-light"), DARK_LINK_WEIGHT)};
  --bn-adm-radius: 0.4rem;
  --bn-adm-margin-block: 24px;
  --bn-adm-padding-inline: 20px;
  --bn-adm-padding-block-end: 16px;
  --bn-adm-title-gap: 12px;
  --bn-adm-title-padding-block: 8px;
  --bn-adm-title-font-size: 18px;
  --bn-adm-title-font-weight: 700;
  --bn-adm-title-line-height: 1.4;
  --bn-adm-title-letter-spacing: 0;
  --bn-adm-title-text-transform: none;
  --bn-adm-icon-size: 22px;
  --bn-adm-icon-gap: 12px;
{color_lines}
{icon_lines}
}}"""


def zensical_selector(names):
    return ".md-typeset .admonition:is(" + ", ".join(f".{name}" for name in names) + ")"


zensical_parts = ["""\
.md-typeset .admonition {
  margin: var(--bn-adm-margin-block) 0;
  padding: 0 var(--bn-adm-padding-inline) var(--bn-adm-padding-block-end);
  overflow: hidden;
  border: 0;
  border-radius: var(--bn-adm-radius);
  background: var(--bn-adm-card-bg);
  color: var(--bn-adm-card-fg);
}

.md-typeset .admonition > .admonition-title + * {
  margin-top: 0;
}

.md-typeset .admonition > :last-child {
  margin-bottom: 0 !important;
}

.md-typeset .admonition a {
  color: inherit;
  text-decoration: underline;
}

.md-typeset .admonition code {
  color: inherit;
  background: rgba(128, 128, 128, 0.18);
}

.md-typeset .admonition > .admonition-title {
  position: relative;
  margin: 0 calc(-1 * var(--bn-adm-padding-inline)) var(--bn-adm-title-gap);
  padding: var(--bn-adm-title-padding-block) var(--bn-adm-padding-inline)
    var(--bn-adm-title-padding-block)
    calc(var(--bn-adm-padding-inline) + var(--bn-adm-icon-size) + var(--bn-adm-icon-gap));
  border-radius: 0;
  background: transparent;
  color: inherit;
  font-family: inherit;
  font-size: var(--bn-adm-title-font-size);
  font-weight: var(--bn-adm-title-font-weight);
  line-height: var(--bn-adm-title-line-height);
  letter-spacing: var(--bn-adm-title-letter-spacing);
  text-transform: var(--bn-adm-title-text-transform);
}

.md-typeset .admonition > .admonition-title::before {
  position: absolute;
  top: 50%;
  left: var(--bn-adm-padding-inline);
  width: var(--bn-adm-icon-size);
  height: var(--bn-adm-icon-size);
  transform: translateY(-55%);
  background-color: currentColor;
  -webkit-mask-image: var(--bn-adm-card-icon);
  mask-image: var(--bn-adm-card-icon);
  -webkit-mask-repeat: no-repeat;
  mask-repeat: no-repeat;
  -webkit-mask-size: contain;
  mask-size: contain;
}"""]

for family, values in FAMILIES.items():
    selector = zensical_selector(values["zensical"])
    zensical_parts.append(
        f"""\
{selector} {{
{variable_lines(family)}
  background-color: var(--bn-adm-card-bg);
  color: var(--bn-adm-card-fg);
}}"""
    )


def sphinx_selector(values):
    selectors = []
    if values["sphinx"]:
        selectors.append(
            ".rst-content :is(" + ", ".join(f".{name}" for name in values["sphinx"]) + ")"
        )
    if alert := values.get("sphinx_alert"):
        selectors.append(f".rst-content .wy-alert-{alert}")
        selectors.append(f".wy-alert.wy-alert-{alert}")
    return ",\n".join(selectors)


sphinx_parts = []
for family, values in FAMILIES.items():
    if selector := sphinx_selector(values):
        sphinx_parts.append(f"{selector} {{\n{variable_lines(family)}\n}}")

doxygen_parts = []
for family, values in FAMILIES.items():
    if values["doxygen"]:
        selector = "dl:is(" + ", ".join(f".{name}" for name in values["doxygen"]) + ")"
        doxygen_parts.append(f"{selector} {{\n{variable_lines(family)}\n}}")

rust_parts = []
for family, values in FAMILIES.items():
    if values.get("rust"):
        rust_parts.append(
            ".content .docblock div.warning {\n" + variable_lines(family) + "\n}"
        )

OUTPUTS = {
    API / "docs" / "manual" / "brand.css": brand_block,
    API / "docs" / "manual" / "docs.css": "\n\n".join(zensical_parts),
    API / "docs" / "reference" / "python" / "source" / "_static" / "css" / "other.css": "\n\n".join(sphinx_parts),
    API / "docs" / "reference" / "cpp" / "binaryninja-docs.css": "\n\n".join(doxygen_parts),
    API / "rust" / "rustdoc-brand.css": "\n\n".join(rust_parts),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if generated CSS is not current without modifying files",
    )
    args = parser.parse_args()

    stale = []
    for path, generated in OUTPUTS.items():
        expected = fenced_source(path, generated)
        if expected == path.read_text():
            continue
        if args.check:
            stale.append(path.relative_to(API))
        else:
            path.write_text(expected)

    if stale:
        for path in stale:
            print(f"stale generated admonition CSS: {path}", file=sys.stderr)
        print("run scripts/gen_admonitions.py to regenerate", file=sys.stderr)
        return 1

    action = "verified" if args.check else "regenerated"
    print(f"{action} shared admonition tokens and backend mappings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
