import os
import re
import stat
import requests
import argparse
import time
from uuid import uuid4
from pprint import pprint
from packageurl import PackageURL
from collections import defaultdict

from cyclonedx.builder.this import this_component as cdx_lib_component
from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.output import make_outputter
from cyclonedx.output.json import JsonV1Dot5
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.model.vulnerability import (
    Vulnerability,
    VulnerabilityRating,
    VulnerabilityScoreSource
)


def parse_module(mod_str, module_names):
    """
    Parse a module string to find the longest valid module name from a set of known module names.

    Args:
        mod_str (str): The module string to parse
        module_names (set): Set of valid module names

    Returns:
        str: The longest valid module name found in the string, or None if no match found
    """
    mod_lst = mod_str.split('-')
    if mod_lst[-1] in module_names:
        return mod_lst[-1]
    else:
        for i in range(len(mod_lst)):
            if '-'.join(mod_lst[i:]) in module_names:
                return '-'.join(mod_lst[i:])


def parse_makefile_def(file_path):
    """
    Parse Makefile.def and extract explicitly declared dependencies.

    Args:
        file_path (str): Path to the Makefile.def file

    Returns:
        dict: Dictionary with module names as keys and their direct dependencies as values
    """
    dependencies = defaultdict(list)
    module_names = set()

    with open(file_path, 'r') as f:
        content = f.read()
        for match in re.finditer(
            r'(?:host_modules|target_modules)\s*=\s*{\s*module\s*=\s*([^;]+)',
            content
        ):
            module = match.group(1).strip()
            module_names.add(module)

        for match in re.finditer(
            r'dependencies\s*=\s*{\s*module\s*=\s*([^;]+);\s*on\s*=\s*([^;]+);',
            content
        ):
            module_raw = match.group(1).strip()
            module = parse_module(module_raw, module_names)
            dep_raw = match.group(2).strip()
            dep = parse_module(dep_raw, module_names)
            if module in module_names and dep in module_names:
                if dep not in dependencies[module]:
                    dependencies[module].append(dep)
    return dict(dependencies)


def try_to_find_version(directory, package_name):
    """
    Attempt to find the version of a package by searching through files in a directory.

    Args:
        directory (str): Directory path to search for version information
        package_name (str): Name of the package to find version for

    Returns:
        str: Found version string, or empty string if not found
    """
    version_patterns = [
        (r"\b\d+\.\d+\.\d+\b", lambda f: "VER" in f),
        (r"#define\s+\w*VERSION\s+([^\s]+)", [f"{package_name}.h"]),
    ]

    raw_found_versions = set()

    for pattern, files_or_condition in version_patterns:
        if callable(files_or_condition):
            for root, _, files in os.walk(directory):
                for file in files:
                    if files_or_condition(file):
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r', encoding='utf-8') as f:
                                content = f.read()
                            matches = re.findall(pattern, content)
                            if matches:
                                raw_found_versions.update(matches)
                        except (IOError, UnicodeDecodeError):
                            continue
        else:
            for filename in files_or_condition:
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read()
                        matches = re.findall(pattern, content)
                        if matches:
                            raw_found_versions.update(matches)
                    except (IOError, UnicodeDecodeError):
                        continue

    found_versions = []
    for version in raw_found_versions:
        found_versions.append(version.replace("\"", ""))

    if found_versions:
        return found_versions[0]
    else:
        return ""


def add_dependencies(comp_refs, bom, root_dir):
    """
    Add dependencies between components to the BOM based on Makefile.def.

    Args:
        comp_refs (dict): Dictionary of component references
        bom (Bom): The Bill of Materials object
        root_dir (str): Root directory containing Makefile.def
    """
    dep_dict = parse_makefile_def(root_dir + "/Makefile.def")
    for comp_name in dep_dict:
        if comp_name in comp_refs.keys() or comp_name == "libcpp":
            component = comp_refs["cpplib" if comp_name == "libcpp" else comp_name]
            for dep_name in dep_dict[comp_name]:
                if dep_name == "libcpp":
                    bom.register_dependency(comp_refs["cpplib"], [component])
                elif dep_name in comp_refs.keys():
                    bom.register_dependency(comp_refs[dep_name], [component])


def send_nvd_request(vendor, package_name, version):
    """
    Search for CVEs in the NVD database for a specific package.

    Args:
        vendor (str): Vendor name
        package_name (str): Package name
        version (str): Package version

    Returns:
        list: List of dictionaries containing CVE details, or None if no CVEs found
    """
    time.sleep(10)
    cves = []
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cpeName": "cpe:2.3:a:{0}:{1}:{2}:*:*:*:*:*:*:*".format(
            vendor, package_name, version
        )
    }
    response = requests.get(url, params=params)

    if response.status_code == 200:
        data = response.json()
        for vulnerability in data.get("vulnerabilities", []):
            cve_info = vulnerability.get("cve", {})
            cve_id = cve_info.get("id")
            cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            metrics = cve_info.get("metrics", {})
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get(
                "cvssData", {}).get("baseScore")
            cvss_v3 = metrics.get("cvssMetricV30", [{}])[0].get(
                "cvssData", {}).get("baseScore")

            if cve_id:
                cves.append({
                    "CVE_ID": cve_id,
                    "URL": cve_url,
                    "SCORES": [
                        [VulnerabilityScoreSource.CVSS_V2, cvss_v2],
                        [VulnerabilityScoreSource.CVSS_V3, cvss_v3],
                    ]
                })

    return cves if cves else None


def search_nvd(package_name, version):
    """
    Search for CVEs in the NVD database for a given package name and version.
    Tries common vendor names if the first attempt fails.

    Args:
        package_name (str): Package name to search
        version (str): Package version

    Returns:
        list: List of CVEs found, or empty list if none found
    """
    cves = send_nvd_request("gnu", package_name, version)
    if cves:
        return cves
    else:
        cves = send_nvd_request(package_name, package_name, version)
        if cves:
            return cves
    return []


def add_library_to_bom(bom, package_name, name_from_path, ver_parsed):
    """
    Add a library component to the BOM with its vulnerabilities.

    Args:
        bom (Bom): The Bill of Materials object
        package_name (str): Official package name
        name_from_path (str): Name derived from file path
        ver_parsed (str): Parsed version string

    Returns:
        Component: The created library component
    """
    bom_ref = str(uuid4())
    component = Component(
        type=ComponentType.LIBRARY,
        name=package_name if package_name not in ("", 'package-unused') else name_from_path,
        version=ver_parsed if ver_parsed not in (' ', "version-unused") else "",
        bom_ref=bom_ref
    )
    return component


def add_vulnerabilites(bom, package_name, component):
    """
    Add vulnerabilities to a component in the BOM by searching NVD database.

    Args:
        bom (Bom): The Bill of Materials object
        package_name (str): Name of the package to search vulnerabilities for
        component (Component): The component to add vulnerabilities to
    """
    cves = search_nvd(package_name, component.version)
    for vuln in cves:
        rating = []
        for scr in vuln["SCORES"]:
            rating.append(VulnerabilityRating(score=scr[1], method=scr[0]))
        vulnerability = Vulnerability(
            bom_ref=component.bom_ref,
            id=vuln["CVE_ID"],
            source=vuln["URL"],
            ratings=set(rating)
        )
        bom.vulnerabilities.add(vulnerability)


def scan_directory(path):
    """
    Scan a directory and generate a Software Bill of Materials (SBOM).

    Args:
        path (str): Path to the directory to scan
    """
    bom = Bom()
    bom.metadata.tools.components.add(cdx_lib_component())
    bom.metadata.tools.components.add(Component(
        name='sbom-generator',
        type=ComponentType.APPLICATION,
    ))

    if not os.path.exists(path):
        print(f"Path {path} does not exist.")
        return

    comp_refs = dict()
    pathes_to_components = dict()

    for root, dirs, files in os.walk(path):
        if "configure" in files:
            file_path = os.path.join(root, "configure")
            try:
                flag = False
                name = str()
                tar_name = str()

                with open(file_path, 'r', encoding='utf-8') as file:
                    for line_number, line in enumerate(file, start=1):
                        if "PACKAGE_NAME=" in line:
                            flag = True
                            package_name = line.strip().replace("'", "").split("=")[-1]

                        if "PACKAGE_TARNAME=" in line:
                            tar_name = line.strip().replace("'", "").split("=")[-1]

                        if "PACKAGE_VERSION=" in line:
                            ver_parsed = line.strip().replace("'", "").split("=")[-1]

                            if flag:
                                name_from_path = file_path.split('/')[2]
                                if not ver_parsed:
                                    ver_parsed = try_to_find_version(root, name_from_path)
                                component = add_library_to_bom(
                                    bom, package_name, name_from_path, ver_parsed
                                )
                                if tar_name and package_name != "package-unused":
                                    comp_refs[tar_name] = component
                                    pathes_to_components[tar_name] = root
                                else:
                                    comp_refs[name_from_path] = component
                                    pathes_to_components[name_from_path] = root
            except (UnicodeDecodeError, PermissionError):
                continue

    components_to_add = []
    for name in pathes_to_components:
        most_val = ""
        for sub_name in pathes_to_components:
            if (sub_name != name and
                    pathes_to_components[sub_name] in pathes_to_components[name]):
                if len(sub_name) > len(most_val):
                    most_val = sub_name
        if most_val:
            comp_refs[most_val].components.add(comp_refs[name])
        else:
            components_to_add.append(comp_refs[name])

    for comp in components_to_add:
        bom.components.add(comp)

    for comp in comp_refs:
        add_vulnerabilites(bom, comp, comp_refs[comp])

    add_dependencies(comp_refs, bom, path)
    my_json_outputter = JsonV1Dot5(bom)
    serialized_json = my_json_outputter.output_as_string(indent=2)
    print(serialized_json)
    my_json_validator = JsonStrictValidator(SchemaVersion.V1_6)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a cyclonedx sbom file for gcc 4.1.1 based on its source code"
    )
    parser.add_argument("-i", required=True,
                       help="Root directory of the project.")
    args = parser.parse_args()
    components = scan_directory(args.i)
