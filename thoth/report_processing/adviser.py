#!/usr/bin/env python3
# thoth-report-processing
# Copyright(C) 2020 Francesco Murdaca, Sai Sankar Gochhayat
#
# This program is free software: you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""Utils Create Markdown output from adviser report input."""

import pandas as pd
from typing import Dict, Any


class Adviser:
    """Helper util methods for Adviser report."""

    @staticmethod
    def create_pretty_report_from_json(report: Dict[Any, Any], is_justification: bool = False) -> str:
        """Create Markdown output from adviser report input."""
        md = ""
        if not report:
            return md

        products = report.get("products")
        if not products:
            return md

        md = "Report"

        md += "\n\n" + "Justifications"

        final_df = pd.DataFrame(columns=["message", "type"])

        counter = 0
        # Consider the first product
        product = products[0]

        if "justification" in product.keys():
            justifications = product["justification"]

            if justifications:

                for justification in justifications:
                    final_df.loc[counter] = pd.DataFrame([justification]).iloc[0]
                    counter += 1

        md += "\n\n" + final_df.to_markdown()

        if is_justification:
            return md

        # Packages in Advised Pipfile
        md += Adviser._add_packages_in_advised_pipfile_to_md_report(product=product, is_dev=False)

        # Dev-Packages in Advised Pipfile
        md += Adviser._add_packages_in_advised_pipfile_to_md_report(product=product, is_dev=True)

        requirements = product["project"]["requirements"]

        if "requires" in requirements:
            if requirements["requires"]:
                md += "\n\n" + "Requires in Advised Pipfile"
                df = pd.DataFrame([requirements["requires"]])
                md += "\n\n" + df.to_markdown()

        if "source" in requirements:
            if requirements["source"]:
                md += "\n\n" + "Source in Advised Pipfile"
                df = pd.DataFrame(requirements["source"])
                md += "\n\n" + df.to_markdown()

        # Packages in Advised Pipfile.lock
        md += Adviser._add_packages_in_advised_pipfile_lock_to_md_report(product=product, is_dev=False)

        # Dev-Packages in Advised Pipfile.lock
        md += Adviser._add_packages_in_advised_pipfile_lock_to_md_report(product=product, is_dev=True)

        # Runtime Environment
        md += Adviser._add_runtime_environment_to_md_report(product=product)

        if "score" in product:
            if product["score"]:
                md += "\n\n" + "Software Stack Score"
                df = pd.DataFrame([{"score": product["score"]}])
                md += "\n\n" + df.to_markdown()

        return md

    @staticmethod
    def _add_packages_in_advised_pipfile_to_md_report(product: Dict[Any, Any], is_dev: bool) -> str:
        """Add Packages in Advised Pipfile to final report."""
        md_report = ""

        if is_dev:
            packages = "dev-packages"
        else:
            packages = "packages"

        if not product["project"]["requirements"][packages]:
            return md_report

        if is_dev:
            md_report += "\n\n" + "Dev-Packages in Advised Pipfile"
        else:
            md_report += "\n\n" + "Packages in Advised Pipfile"

        packages_names = []
        packages_versions = []

        for package_name, requested_version in product["project"]["requirements"][packages].items():
            packages_names.append(package_name)
            packages_versions.append(requested_version)

        data = {"package_name": packages_names, "package_version": packages_versions}

        df = pd.DataFrame(data)
        md_report += "\n\n" + df.to_markdown()

        return md_report

    @staticmethod
    def _add_packages_in_advised_pipfile_lock_to_md_report(product: Dict[Any, Any], is_dev: bool) -> str:
        """Add Packages in Advised Pipfile.lock to final report."""
        md_report = ""

        if is_dev:
            packages = "develop"
        else:
            packages = "default"

        if not product["project"]["requirements_locked"][packages]:
            return md_report

        if is_dev:
            md_report += "\n\n" + "Dev-Packages in Advised Pipfile.lock"
        else:
            md_report += "\n\n" + "Packages in Advised Pipfile.lock"

            packages_names = []
            packages_versions = []
            packages_indexes = []

            for package_name, data in product["project"]["requirements_locked"][packages].items():
                packages_names.append(package_name)
                packages_versions.append(data["version"])
                packages_indexes.append(data["index"])

            data = {"package_name": packages_names, "package_version": packages_versions, "index": packages_indexes}
            df = pd.DataFrame(data)
            md_report += "\n\n" + df.to_markdown()

        return md_report

    @staticmethod
    def _add_runtime_environment_to_md_report(product: Dict[Any, Any]) -> str:
        """Add Packages in Advised Pipfile.lock to final report."""
        md_report = ""

        if not product["project"]["runtime_environment"]:
            return md_report

        runtime_environment = product["project"]["runtime_environment"]
        md_report += "\n\n" + "Runtime Environment"

        if "name" in runtime_environment:
            if runtime_environment["name"]:
                md_report += "\n\n" + "Runtime Environment - Name"
                df = pd.DataFrame([{"name": runtime_environment["name"]}])
                md_report += "\n\n" + df.to_markdown()

        if "cuda_version" in runtime_environment:
            if runtime_environment["cuda_version"]:
                md_report += "\n\n" + "Runtime Environment - CUDA"
                df = pd.DataFrame([{"cuda_version": runtime_environment["cuda_version"]}])
                md_report += "\n\n" + df.to_markdown()

        if "hardware" in runtime_environment:
            if [h for h in runtime_environment["hardware"].keys() if runtime_environment["hardware"][h]]:
                md_report += "\n\n" + "Runtime Environment - Hardware"
                df = pd.DataFrame([runtime_environment["hardware"]])
                md_report += "\n\n" + df.to_markdown()

        return md_report
