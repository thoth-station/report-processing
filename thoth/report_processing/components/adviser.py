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


    RESULTS_STORE = SecurityIndicatorsResultsStore

    def aggregate_adviser_results(
        self,
        adviser_version: str,
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = True,
        repo_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Aggregate results stored on Ceph or locally from repo for Thoth components reports.

        :param limit_results: reduce the number of reports ids considered to `max_ids`.
        :param max_ids: maximum number of reports ids considered.
        :param is_local: flag to retrieve the dataset locally (if not uses Ceph S3 (credentials are required)).
        :param repo_path: required if you want to retrieve the dataset locally and `is_local` is set to True.
        """
        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids}!")

        files: Dict[str, Any] = {}

        if is_local:
            files, counter = self._aggregate_thoth_results_from_local(
                adviser_version=adviser_version, repo_path=repo_path, files=files, limit_results=limit_results, max_ids=max_ids,
            )

        else:
            files, counter = self._aggregate_thoth_results_from_ceph(
                adviser_version=adviser_version, files=files, limit_results=limit_results, max_ids=max_ids
            )

        _LOGGER.info("Number of files retrieved is: %r" % counter)

        return files

    @staticmethod
    def _aggregate_thoth_results_from_local(
        files: Dict[str, Any],
        store_files: Optional[List[str]] = None,
        repo_path: Optional[Path] = None,
        limit_results: bool = False,
        max_ids: int = 5,
        is_multiple: Optional[bool] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from local repo."""
        _LOGGER.info(f"Retrieving dataset at path... {repo_path}")
        if not repo_path:
            return files, 0

        if not repo_path.exists():
            raise ThothMissingDatasetAtPath(f"There is no dataset at this path: {repo_path}.")

        counter = 0

        for result_path in repo_path.iterdir():
            _LOGGER.info(f"Considering... {result_path}")

            if "security-indicators" not in result_path.name:
                raise Exception(f"This repo is not part of Security Indicators! {result_path}")

            retrieved_files: Dict[str, Any] = {result_path.name: {}}

            for file_path in result_path.iterdir():

                if store_files and file_path.name in store_files:
                    with open(file_path, "r") as json_file_type:
                        json_file = json.load(json_file_type)

                    retrieved_files[result_path.name][file_path.name] = json_file

            files[result_path.name] = retrieved_files[result_path.name]

            counter += 1

            if limit_results:
                if counter == max_ids:
                    return files, counter

        return files, counter

    def _aggregate_thoth_results_from_ceph(
        self,
        files: Dict[str, Any],
        store_files: Optional[List[str]] = None,
        limit_results: bool = False,
        max_ids: int = 5,
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from Ceph."""
        adviser_store = AdvisersResultsStore()
        adviser_store.connect()

        adviser_ids = list(adviser_store.get_document_listing())

        _LOGGER.info("Number of Adviser reports identified is: %r" % len(adviser_ids))

        adviser_dict = {}
        number_adviser_results = len(adviser_ids)

        counter = 0

        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids} to test functions!!")

        for n, ids in enumerate(adviser_ids):
            _LOGGER.debug(f"Analysis {ids} n.{counter + 1}/{number_adviser_results}")

            try:
                document = adviser_store.retrieve_document(ids)

                datetime = document["metadata"].get("datetime")
                analyzer_version = document["metadata"].get("analyzer_version")

                result = document["result"]

                if int("".join(analyzer_version.split("."))) >= int("".join(adviser_version.split("."))):
                    report = result.get("report")
                    error = result["error"]

                    if error:
                        error_msg = result["error_msg"]
                        adviser_dict[ids] = {
                            "justification": [{"message": error_msg, "type": "ERROR"}],
                            "error": error,
                            "message": error_msg,
                            "type": "ERROR",
                        }
                    else:
                        adviser_dict = extract_adviser_justifications(report=report, adviser_dict=adviser_dict, ids=ids)

                if ids in adviser_dict.keys():
                    adviser_dict[ids]["datetime"] = datetime.strptime(datetime, "%Y-%m-%dT%H:%M:%S.%f")
                    adviser_dict[ids]["analyzer_version"] = analyzer_version

                current_a_counter += 1

                if limit_results:
                    if current_a_counter > max_ids:
                        return _create_adviser_dataframe(adviser_dict)

                files[ids] = retrieved_files[security_indicator_id]

                counter += 1

                _LOGGER.info("Documents retrieved: %r", counter)

                if limit_results:
                    if counter == max_ids:
                        return files, counter

            except Exception as si_exception:
                _LOGGER.exception(
                    f"Exception during retrieval of SI result {security_indicator_id}: {si_exception}"
                )
                pass

        return files, counter

def aggregate_adviser_results(adviser_version: str, limit_results: bool = False, max_ids: int = 5) -> pd.DataFrame:
    """Aggregate adviser results from jsons stored in Ceph.

    :param adviser_version: minimum adviser version considered for the analysis of adviser runs
    :param limit_results: reduce the number of adviser runs ids considered to `max_ids` to test analysis
    :param max_ids: maximum number of adviser runs ids considered
    """
    adviser_store = AdvisersResultsStore()
    adviser_store.connect()

    adviser_ids = list(adviser_store.get_document_listing())

    _LOGGER.info("Number of Adviser reports identified is: %r" % len(adviser_ids))

    adviser_dict = {}
    number_adviser_results = len(adviser_ids)
    current_a_counter = 1

    if limit_results:
        _LOGGER.debug(f"Limiting results to {max_ids} to test functions!!")

    for n, ids in enumerate(adviser_ids):
        try:
            document = adviser_store.retrieve_document(ids)
            datetime_advise_run = document["metadata"].get("datetime")
            analyzer_version = document["metadata"].get("analyzer_version")
            _LOGGER.debug(f"Analysis n.{current_a_counter}/{number_adviser_results}")
            result = document["result"]
            _LOGGER.debug(ids)
            if int("".join(analyzer_version.split("."))) >= int("".join(adviser_version.split("."))):
                report = result.get("report")
                error = result["error"]
                if error:
                    error_msg = result["error_msg"]
                    adviser_dict[ids] = {
                        "justification": [{"message": error_msg, "type": "ERROR"}],
                        "error": error,
                        "message": error_msg,
                        "type": "ERROR",
                    }
                else:
                    adviser_dict = extract_adviser_justifications(report=report, adviser_dict=adviser_dict, ids=ids)

            if ids in adviser_dict.keys():
                adviser_dict[ids]["datetime"] = datetime.strptime(datetime_advise_run, "%Y-%m-%dT%H:%M:%S.%f")
                adviser_dict[ids]["analyzer_version"] = analyzer_version

            current_a_counter += 1

            if limit_results:
                if current_a_counter > max_ids:
                    return _create_adviser_dataframe(adviser_dict)

        except Exception as e:
            _LOGGER.warning(e)

    return _create_adviser_dataframe(adviser_dict)

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
