"""
Package search functionality using direct eix queries.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from subprocess import CompletedProcess
from typing import List

from lxml import etree

from carnage.core.config import Configuration, get_config
from carnage.core.eix import has_remote_cache

logger = logging.getLogger(__name__)


@dataclass
class PackageVersion:
    """Represents a specific version of a package."""
    id: str
    eapi: str | None
    repository: str | None
    virtual: bool
    installed: bool
    src_uri: str | None
    iuse: List[str]
    iuse_default: List[str]
    required_use: str | None
    depend: str | None
    rdepend: str | None
    bdepend: str | None
    pdepend: str | None
    idepend: str | None
    masks: List[str]
    unmasks: List[str]
    properties: List[str]
    restricts: List[str]
    use_enabled: List[str]
    use_disabled: List[str]


@dataclass
class Package:
    """Represents a Gentoo package with all its versions."""
    category: str
    name: str
    description: str | None
    homepage: str | None
    licenses: List[str]
    versions: List[PackageVersion] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.category}/{self.name}"

    def __str__(self) -> str:
        return self.full_name

    def __repr__(self) -> str:
        return f"Package({self.full_name!r}, versions={len(self.versions)})"

    def is_installed(self) -> bool:
        return any(v.installed for v in self.versions)

    def installed_version(self) -> PackageVersion | None:
        for v in self.versions:
            if v.installed:
                return v
        return None

    def is_in_world_file(self) -> bool:
        try:
            result: CompletedProcess[str] = subprocess.run(
                ["eix", "--selected-file", "-0Qq", self.full_name],
                capture_output=True,
                text=True,
                check=False
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def is_installed_dependency(self) -> bool:
        try:
            result: CompletedProcess[str] = subprocess.run(
                ["eix", "--installed-deps", "-0Qq", self.full_name],
                capture_output=True,
                text=True,
                check=False
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_version(version_elem: etree._Element) -> PackageVersion:
    iuse = []
    iuse_default = []

    for iuse_elem in version_elem.xpath("iuse"):
        flags = iuse_elem.text.split() if iuse_elem.text else []
        for flag in flags:
            iuse.append(flag)
            if iuse_elem.get("default") == "1":
                iuse_default.append(flag)

    masks = version_elem.xpath("mask/@type")
    unmasks = version_elem.xpath("unmask/@type")
    properties = version_elem.xpath("properties/@flag")
    restricts = version_elem.xpath("restrict/@flag")

    use_enabled_elems = version_elem.xpath('use[@enabled="1"]')
    use_disabled_elems = version_elem.xpath('use[@enabled="0"]')

    use_enabled = use_enabled_elems[0].text.split() if use_enabled_elems and use_enabled_elems[0].text else []
    use_disabled = use_disabled_elems[0].text.split() if use_disabled_elems and use_disabled_elems[0].text else []

    depend_elem = version_elem.xpath("depend")[0] if version_elem.xpath("depend") else None
    rdepend_elem = version_elem.xpath("rdepend")[0] if version_elem.xpath("rdepend") else None
    bdepend_elem = version_elem.xpath("bdepend")[0] if version_elem.xpath("bdepend") else None
    pdepend_elem = version_elem.xpath("pdepend")[0] if version_elem.xpath("pdepend") else None
    idepend_elem = version_elem.xpath("idepend")[0] if version_elem.xpath("idepend") else None
    required_use_elem = version_elem.xpath("required_use")[0] if version_elem.xpath("required_use") else None

    return PackageVersion(
        id=version_elem.get("id", ""),
        eapi=version_elem.get("EAPI"),
        repository=version_elem.get("repository"),
        virtual=version_elem.get("virtual") == "1",
        installed=version_elem.get("installed") == "1",
        src_uri=version_elem.get("srcURI"),
        iuse=iuse,
        iuse_default=iuse_default,
        required_use=required_use_elem.text if required_use_elem is not None else None,
        depend=depend_elem.text if depend_elem is not None else None,
        rdepend=rdepend_elem.text if rdepend_elem is not None else None,
        bdepend=bdepend_elem.text if bdepend_elem is not None else None,
        pdepend=pdepend_elem.text if pdepend_elem is not None else None,
        idepend=idepend_elem.text if idepend_elem is not None else None,
        masks=masks,
        unmasks=unmasks,
        properties=properties,
        restricts=restricts,
        use_enabled=use_enabled,
        use_disabled=use_disabled
    )


def _parse_package(package_elem: etree._Element, category: str) -> Package:
    name = package_elem.get("name", "")
    desc_elem = package_elem.xpath("description")[0] if package_elem.xpath("description") else None
    homepage_elem = package_elem.xpath("homepage")[0] if package_elem.xpath("homepage") else None
    licenses_elem = package_elem.xpath("licenses")[0] if package_elem.xpath("licenses") else None

    licenses = licenses_elem.text.split() if licenses_elem is not None and licenses_elem.text else []

    version_elems = package_elem.xpath("version")
    versions = [_parse_version(v) for v in version_elems]

    return Package(
        category=category,
        name=name,
        description=desc_elem.text if desc_elem is not None else None,
        homepage=homepage_elem.text if homepage_elem is not None else None,
        licenses=licenses,
        versions=versions
    )


# ---------------------------------------------------------------------------
# Fetch packages
# ---------------------------------------------------------------------------

def fetch_packages_by_query(query: List[str], append_cfg: bool = True) -> List[Package]:
    if has_remote_cache():
        cmd: list[str] = ["eix", "-RQ", "--xml"]
    else:
        cmd = ["eix", "-Q", "--xml"]

    if append_cfg:
        config: Configuration = get_config()
        cmd.extend(config.search_flags)

    cmd.extend(query)
    logger.debug("Running eix query: %s", " ".join(cmd))

    try:
        result: CompletedProcess[str] = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        parser = etree.XMLParser(recover=True, remove_comments=True)
        root = etree.fromstring(result.stdout.encode("utf-8"), parser=parser)

        packages: List[Package] = []
        for category_elem in root.xpath("//category"):
            cat_name = category_elem.get("name", "")
            for package_elem in category_elem.xpath("package"):
                packages.append(_parse_package(package_elem, cat_name))

        return packages

    except subprocess.CalledProcessError as e:
        logger.error("eix query failed: %s", e)
        return []
    except etree.XMLSyntaxError as e:
        logger.error("Failed to parse eix XML: %s", e)
        return []


def search_packages(query: str) -> List[Package]:
    if not query.strip():
        return []

    query_args = query.split()
    has_flags = any(arg.startswith('-') for arg in query_args)
    append_cfg = not has_flags

    return fetch_packages_by_query(query_args, append_cfg=append_cfg)


def get_package_by_atom(atom: str) -> Package | None:
    try:
        packages = fetch_packages_by_query([atom])
        for pkg in packages:
            if pkg.full_name == atom:
                return pkg
        return None
    except Exception as e:
        logger.error("Failed to get package by atom %s: %s", atom, e)
        return None
