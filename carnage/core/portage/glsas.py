"""
Utilities for managing Gentoo Linux Security Advisories (GLSAs).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from lxml import etree

from carnage.core.portage.portageq import get_gentoo_repo_path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AffectedPackage:
    name: str
    auto: str
    arch: str
    unaffected_conditions: list[dict]
    vulnerable_conditions: list[dict]

    def __str__(self) -> str:
        return self.name


@dataclass
class Resolution:
    text: str
    code: str | None = None

    def __str__(self) -> str:
        return self.text


@dataclass
class GLSA:
    id: str
    title: str | None
    synopsis: str
    product: str | None
    announced: str | None
    revised: str | None
    revision_count: str
    bugs: list[str]
    access: str | None
    background: str | None
    description: str
    impact: str
    impact_type: str
    workaround: str | None
    resolutions: list[Resolution]
    affected_packages: list[AffectedPackage]
    references: list[str]

    def __str__(self) -> str:
        return f"{self.id}: {self.title}"


# ---------------------------------------------------------------------------
# GLSA command helpers
# ---------------------------------------------------------------------------

def get_affected_glsas() -> tuple[int, str]:
    """
    Get GLSAs that affect the system.

    Wraps: glsa-check -tqn all
    """
    logger.info("Checking for affected GLSAs")

    # Lazy import to avoid circular dependency
    from carnage.core.privilege import run_privileged

    rc, out, err = run_privileged(
        ["glsa-check", "-tqn", "all"],
        use_terminal=False,
    )

    logger.debug("glsa-check return code: %s", rc)
    if out:
        logger.debug("glsa-check stdout:\n%s", out)
    if err:
        logger.warning("glsa-check stderr:\n%s", err)

    return rc, out.strip()


def fix_glsas() -> tuple[int, str, str]:
    """
    Fix all GLSAs affecting the system.

    Wraps: glsa-check -f <glsa list>
    """
    rc, glsa_list = get_affected_glsas()

    if rc == 0 or not glsa_list:
        logger.info("No GLSAs affecting the system")
        return 0, "No GLSAs affecting the system.", ""

    glsas = glsa_list.split()
    logger.info("Fixing GLSAs: %s", ", ".join(glsas))

    # Lazy import to avoid circular dependency
    from carnage.core.privilege import run_privileged

    rc, out, err = run_privileged(
        ["glsa-check", "-f", *glsas],
        use_terminal=True,
    )

    logger.debug("glsa-check -f return code: %s", rc)
    if out:
        logger.debug("stdout:\n%s", out)
    if err:
        logger.warning("stderr:\n%s", err)

    return rc, out, err


# ---------------------------------------------------------------------------
# XML parsing helpers
# ---------------------------------------------------------------------------

def _parse_affected_packages(root: etree._Element) -> list[AffectedPackage]:
    packages: list[AffectedPackage] = []

    for pkg in root.xpath("affected/package"):
        unaffected = []
        vulnerable = []

        for elem in pkg.xpath("unaffected"):
            unaffected.append({
                "range": elem.get("range", ""),
                "slot": elem.get("slot", ""),
                "value": (elem.text or "").strip(),
            })

        for elem in pkg.xpath("vulnerable"):
            vulnerable.append({
                "range": elem.get("range", ""),
                "slot": elem.get("slot", ""),
                "value": (elem.text or "").strip(),
            })

        packages.append(
            AffectedPackage(
                name=pkg.get("name", ""),
                auto=pkg.get("auto", "yes"),
                arch=pkg.get("arch", "*"),
                unaffected_conditions=unaffected,
                vulnerable_conditions=vulnerable,
            )
        )

    return packages


def _clean_code_indentation(code: str) -> str:
    lines = code.splitlines()

    min_indent = None
    for line in lines:
        if line.strip():
            indent = len(line) - len(line.lstrip())
            min_indent = indent if min_indent is None else min(min_indent, indent)

    if min_indent:
        return "\n".join(
            line[min_indent:] if line.strip() else line
            for line in lines
        )

    return code


def _parse_resolutions(root: etree._Element) -> list[Resolution]:
    resolutions: list[Resolution] = []

    elems = root.xpath("resolution")
    if not elems:
        return resolutions

    text_buf = ""
    code_buf = ""

    for elem in elems[0].iter():
        if elem.tag == "p":
            if text_buf or code_buf:
                resolutions.append(
                    Resolution(
                        text=text_buf.strip(),
                        code=_clean_code_indentation(code_buf) if code_buf else None,
                    )
                )
                text_buf = ""
                code_buf = ""

            if elem.text:
                text_buf = elem.text.strip()

        elif elem.tag == "code" and elem.text:
            code_buf += elem.text

        if elem.tail and elem.tail.strip():
            text_buf += " " + elem.tail.strip()

    if text_buf or code_buf:
        resolutions.append(
            Resolution(
                text=text_buf.strip(),
                code=_clean_code_indentation(code_buf) if code_buf else None,
            )
        )

    return resolutions


def _parse_glsa_xml(glsa_id: str, path: Path) -> GLSA | None:
    try:
        parser = etree.XMLParser(recover=True, remove_comments=True)
        tree = etree.parse(path, parser)
        root = tree.getroot()

        def s(xpath: str) -> str | None:
            val = root.xpath(f"string({xpath})")
            return val.strip() if val else None

        impact_elem = root.xpath("impact")
        revised_elem = root.xpath("revised")

        return GLSA(
            id=glsa_id,
            title=s("title"),
            synopsis=s("synopsis") or "",
            product=s("product"),
            announced=s("announced"),
            revised=s("revised"),
            revision_count=revised_elem[0].get("count", "01") if revised_elem else "01",
            bugs=[b for b in root.xpath("bug/text()") if b],
            access=s("access"),
            background=s("background/p"),
            description=s("description/p") or "",
            impact=s("impact/p") or "",
            impact_type=impact_elem[0].get("type", "normal") if impact_elem else "normal",
            workaround=s("workaround/p"),
            resolutions=_parse_resolutions(root),
            affected_packages=_parse_affected_packages(root),
            references=[
                uri.get("link") or uri.text
                for uri in root.xpath("references/uri")
                if uri.get("link") or uri.text
            ],
        )

    except Exception as e:
        logger.exception("Failed to parse GLSA %s: %s", glsa_id, e)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fetch_glsas() -> list[GLSA]:
    """
    Fetch all GLSAs affecting the system with full metadata.
    """
    repo = get_gentoo_repo_path()
    glsa_dir = repo / "metadata" / "glsa"

    rc, glsa_codes = get_affected_glsas()
    if rc == 0 or not glsa_codes:
        return []

    glsas: list[GLSA] = []

    for code in glsa_codes.split():
        xml = glsa_dir / f"glsa-{code}.xml"
        if not xml.exists():
            logger.warning("Missing GLSA XML: %s", xml)
            continue

        glsa = _parse_glsa_xml(code, xml)
        if glsa:
            glsas.append(glsa)

    logger.info("Loaded %d GLSAs", len(glsas))
    return glsas
