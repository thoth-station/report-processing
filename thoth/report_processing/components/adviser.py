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

"""Adviser reports processing methods."""

import logging
import os
import json

from datetime import datetime, date
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

import pandas as pd
import numpy as np

from thoth.report_processing.exceptions import ThothMissingDatasetAtPath
from thoth.common import normalize_os_version
from thoth.common import map_os_name
from thoth.storages import CephStore
from thoth.storages.advisers import AdvisersResultsStore

# set up logging
DEBUG_LEVEL = bool(int(os.getenv("DEBUG_LEVEL", 0)))

if DEBUG_LEVEL:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

_LOGGER = logging.getLogger(__name__)


class Adviser:
    """Class of methods used to process results from Adviser."""

    @classmethod
    def aggregate_adviser_results(
        cls,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = False,
        repo_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Aggregate results stored on Ceph or locally from repo for Thoth components reports.

        :param start_date: start date for documents to consider.
        :param end_date: end date for documents to consider.
        :param limit_results: reduce the number of reports ids considered to `max_ids`.
        :param max_ids: maximum number of reports ids considered.
        :param is_local: flag to retrieve the dataset locally (if not uses Ceph S3 (credentials are required)).
        :param repo_path: required if you want to retrieve the dataset locally and `is_local` is set to True.
        """
        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids}!")

        files: Dict[str, Any] = {}

        if not is_local:
            files, counter = cls._aggregate_thoth_results_from_ceph(
                files=files,
                start_date=start_date,
                end_date=end_date,
                limit_results=limit_results,
                max_ids=max_ids,
            )
            _LOGGER.info("Number of files retrieved is: %r" % counter)

            return files

        files, counter = cls._aggregate_thoth_results_from_local(
            repo_path=repo_path,
            files=files,
            limit_results=limit_results,
            max_ids=max_ids,
        )
        _LOGGER.info("Number of files retrieved is: %r" % counter)

        return files

    @staticmethod
    def _aggregate_thoth_results_from_local(
        files: Dict[str, Any],
        repo_path: Optional[Path] = None,
        limit_results: bool = False,
        max_ids: int = 5,
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from local repo."""
        _LOGGER.info(f"Retrieving dataset at path... {repo_path}")
        if not repo_path:
            _LOGGER.warning("No Path has been provided to retrieve data locally.")
            return files, 0

        if not repo_path.exists():
            raise ThothMissingDatasetAtPath(f"There is no dataset at this path: {repo_path}.")

        counter = 0

        for file_path in repo_path.iterdir():
            _LOGGER.info(f"Considering... {file_path}")

            if "adviser" not in file_path.name:
                raise Exception(f"This repo is not part of adviser! {repo_path}")

            with open(file_path, "r") as json_file_type:
                json_file = json.load(json_file_type)

            files[file_path.name] = json_file

            counter += 1

            if limit_results:
                if counter == max_ids:
                    return files, counter

        return files, counter

    @staticmethod
    def _aggregate_thoth_results_from_ceph(
        files: Dict[str, Any],
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        limit_results: bool = False,
        max_ids: int = 5,
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from Ceph."""
        adviser_store = AdvisersResultsStore()
        adviser_store.connect()

        number_adviser_results = adviser_store.get_document_count(start_date=start_date, end_date=end_date)

        _LOGGER.info("Number of Adviser reports identified is: %r" % number_adviser_results)

        document_ids = [idd for idd in adviser_store.get_document_listing(start_date=start_date, end_date=end_date)]

        counter = 0

        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids} to test functions!!")

        for document_id in document_ids:
            _LOGGER.debug(f"Analysis {document_id} n.{counter + 1}/{number_adviser_results}")

            try:
                document = adviser_store.retrieve_document(document_id)

                if "metadata" in document.keys():
                    files[document_id] = document

                    counter += 1

                    _LOGGER.info("Documents retrieved: %r", counter)

                    if limit_results:
                        if counter == max_ids:
                            return files, counter
                else:
                    _LOGGER.warning(f"'metadata' is not present in {document_id} keys!")

            except Exception as exception:
                _LOGGER.exception(f"Exception during retrieval of adviser result {document_id}: {exception}")
                continue

        return files, counter

    @staticmethod
    def _update_statistics(
        statistics: Dict[str, Any],
        analyzer_version: str,
        error_count: int,
        no_report: bool = False,
    ) -> Dict[str, Any]:
        if analyzer_version not in statistics:
            statistics[analyzer_version] = {}

        if analyzer_version not in statistics[analyzer_version]:
            statistics[analyzer_version]["adviser_version"] = analyzer_version
        key = "success"

        if no_report or error_count:
            key = "failure"

        if key not in statistics[analyzer_version]:
            statistics[analyzer_version][key] = 1
        else:
            statistics[analyzer_version][key] += 1

        return statistics

    @classmethod
    def _retrieve_adviser_justifications(
        cls,
        adviser_files: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Retrieve adviser justifications.

        :param adviser_files: adviser documents
        """
        statistics: Dict[str, Any] = {}

        justifications_collected: List[Dict[str, Any]] = []

        for document_id, document in adviser_files.items():

            error_count = 0
            report = {}

            try:
                datetime_advise_run = document["metadata"].get("datetime")
                analyzer_version = document["metadata"].get("analyzer_version")
                datetime_object = datetime.strptime(datetime_advise_run, "%Y-%m-%dT%H:%M:%S.%f")
                result = document["result"]
                report = result.get("report")

            except Exception as report_error:
                _LOGGER.error(f"Error analyzing adviser document {document_id} report stack info: {report_error}")
                _LOGGER.error("Adviser document %s report is: %s", document_id, report)

            if not report:
                _LOGGER.warning(f"No report for adviser document: {document_id}")
                justifications_collected.append(
                    {
                        "document_id": document_id,
                        "date": datetime_object,
                        "analyzer_version": analyzer_version,
                        "justification": "no report provided",
                        "error": True,
                        "message": "no report provided",
                        "type": "ERROR",
                    },
                )

                cls._update_statistics(
                    statistics=statistics,
                    analyzer_version=analyzer_version,
                    error_count=error_count,
                    no_report=True,
                )

                continue

            try:
                justifications_collected, error_count = cls.extract_adviser_justifications_from_stack_info(
                    report=report,
                    justifications_collected=justifications_collected,
                    document_id=document_id,
                    datetime_object=datetime_object,
                    analyzer_version=analyzer_version,
                    error_count=error_count,
                )

            except Exception as stack_info_error:
                _LOGGER.error(f"Error analyzing adviser document {document_id} report stack info: {stack_info_error}")
                _LOGGER.error("Adviser document %s report stack info: %s", document_id, report.get("stack_info"))

            cls._update_statistics(
                statistics=statistics,
                analyzer_version=analyzer_version,
                error_count=error_count,
            )

            try:
                justifications_collected = cls.extract_adviser_justifications_from_products(
                    report=report,
                    justifications_collected=justifications_collected,
                    document_id=document_id,
                    datetime_object=datetime_object,
                    analyzer_version=analyzer_version,
                )
            except Exception as products_error:
                _LOGGER.error(f"Error analyzing adviser document {document_id} report products: {products_error}")
                _LOGGER.error("Adviser document %s report products: %s", document_id, report.get("products"))

        if statistics:
            if "success" not in statistics[analyzer_version]:
                statistics[analyzer_version]["success"] = 0

            if "failure" not in statistics[analyzer_version]:
                statistics[analyzer_version]["failure"] = 0

        return justifications_collected, statistics

    @classmethod
    def create_adviser_justifications_and_statistics_dataframe(
        cls,
        adviser_files: Dict[str, Any],
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Create dataframe of adviser justifications from results."""
        justifications_collected, statistics = cls._retrieve_adviser_justifications(adviser_files=adviser_files)
        adviser_justifications_dataframe = pd.DataFrame(justifications_collected)

        if not adviser_justifications_dataframe.empty:
            adviser_justifications_dataframe["date_"] = [
                pd.to_datetime(str(v_date)).strftime("%Y-%m-%d")
                for v_date in adviser_justifications_dataframe["date"].values
            ]

        adviser_statistics_dataframe = pd.DataFrame(statistics)

        if not adviser_statistics_dataframe.empty:
            # Maintain order not to lose track when storing on csv without headers
            adviser_statistics_dataframe = adviser_statistics_dataframe.transpose()[
                ["adviser_version", "success", "failure"]
            ]
        return adviser_justifications_dataframe, adviser_statistics_dataframe

    @staticmethod
    def _retrieve_adviser_inputs_statistics(
        adviser_files: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Retrieve adviser inputs statistics.

        :param adviser_files: adviser documents
        """
        adviser_inputs_collected: List[Dict[str, Any]] = []

        for document_id, document in adviser_files.items():

            datetime_advise_run = document["metadata"].get("datetime")
            datetime_object = datetime.strptime(datetime_advise_run, "%Y-%m-%dT%H:%M:%S.%f")

            cli_arguments = document["metadata"]["arguments"]["thoth-adviser"]
            source_type = (cli_arguments.get("metadata") or {}).get("source_type")
            source_type = source_type.upper() if source_type else None

            parameters = document["result"]["parameters"]

            runtime_environment = parameters["project"].get("runtime_environment")
            os = runtime_environment.get("operating_system", {})
            if os:
                os_name = runtime_environment["operating_system"].get("name")
                if os_name:
                    runtime_environment["operating_system"]["name"] = map_os_name(
                        os_name=runtime_environment["operating_system"]["name"],
                    )

            # Recommendation type
            recommendation_type = parameters["recommendation_type"].upper()

            # Solver
            os = runtime_environment.get("operating_system", {})
            os_name = os.get("name")
            os_version = normalize_os_version(os.get("name"), os.get("version"))
            python_interpreter = runtime_environment.get("python_version")

            # Base image
            base_image = runtime_environment.get("base_image", None)
            # Hardware
            hardware = runtime_environment.get("hardware", {})
            adviser_inputs_collected.append(
                {
                    "document_id": document_id,
                    "date": datetime_object,
                    "source_type": source_type,
                    "recommendation_type": recommendation_type,
                    "base_image": base_image,
                    "solver": f'{os_name}-{os_version}-py{python_interpreter.replace(".", "")}',
                    "cpu_model": hardware.get("cpu_model", None),
                    "cpu_family": hardware.get("cpu_family", None),
                },
            )

        return adviser_inputs_collected

    @classmethod
    def create_adviser_inputs_info_dataframe(cls, adviser_files: Dict[str, Any]) -> pd.DataFrame:
        """Create dataframe of adviser inputs info from results."""
        adviser_inputs_info_dataframe = pd.DataFrame(
            cls._retrieve_adviser_inputs_statistics(adviser_files=adviser_files),
        )
        if not adviser_inputs_info_dataframe.empty:
            adviser_inputs_info_dataframe["date_"] = [
                pd.to_datetime(str(v_date)).strftime("%Y-%m-%d")
                for v_date in adviser_inputs_info_dataframe["date"].values
            ]
        return adviser_inputs_info_dataframe

    @classmethod
    def create_adviser_dataframes(cls, adviser_files: Dict[str, Any]) -> Dict[str, pd.DataFrame]:
        """Create dataframe of adviser justifications from results."""
        dataframes = {}
        (
            dataframes["justifications"],
            dataframes["statistics"],
        ) = cls.create_adviser_justifications_and_statistics_dataframe(adviser_files=adviser_files)
        dataframes["inputs_info"] = cls.create_adviser_inputs_info_dataframe(adviser_files=adviser_files)

        return dataframes

    @staticmethod
    def extract_adviser_justifications_from_stack_info(
        report: Dict[str, Any],
        justifications_collected: List[Dict[str, Any]],
        document_id: str,
        datetime_object: datetime,
        analyzer_version: str,
        error_count: int,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Retrieve justifications from stack info from adviser report."""
        stack_info = report.get("stack_info")

        if not stack_info:
            _LOGGER.warning("No stack info in report.")
            return justifications_collected, error_count

        for info in stack_info:

            justification = {"message": info["message"], "type": info["type"]}

            if "link" in info:
                message = info["link"]
            else:
                message = info["message"]

            error = False

            if info["type"] == "ERROR":
                error = True
                error_count += 1

            justifications_collected.append(
                {
                    "document_id": document_id,
                    "date": datetime_object,
                    "analyzer_version": analyzer_version,
                    "justification": justification,
                    "error": error,
                    "message": message,
                    "type": info["type"],
                },
            )

        return justifications_collected, error_count

    @classmethod
    def extract_adviser_justifications_from_products(
        cls,
        report: Dict[str, Any],
        justifications_collected: List[Dict[str, Any]],
        document_id: str,
        datetime_object: datetime,
        analyzer_version: str,
    ) -> List[Dict[str, Any]]:
        """Retrieve justifications from products from adviser report."""
        products = report.get("products")
        justifications_collected = cls.extract_justifications_from_products(
            products=products,
            justifications_collected=justifications_collected,
            document_id=document_id,
            datetime_object=datetime_object,
            analyzer_version=analyzer_version,
        )

        return justifications_collected

    @staticmethod
    def extract_justifications_from_products(
        products: Optional[List[Dict[str, Any]]],
        justifications_collected: List[Dict[str, Any]],
        document_id: str,
        datetime_object: datetime,
        analyzer_version: str,
    ) -> List[Dict[str, Any]]:
        """Extract justifications from products in adviser document."""
        if not products:
            _LOGGER.debug(f"No products identified in adviser document: {document_id}")
            return justifications_collected

        # TODO: Handle all products
        product = products[0]
        justifications = product["justification"]

        if justifications:
            # Collect all justifications
            for justification in justifications:

                if "advisory" in justification:

                    error = True
                    message = justification["advisory"]
                    justification_type = justification["type"]

                elif "link" in justification:

                    error = False
                    message = justification["link"]
                    justification_type = justification["type"]

                else:
                    error = False
                    message = justification["message"]
                    justification_type = justification["type"]

                justifications_collected.append(
                    {
                        "document_id": document_id,
                        "date": datetime_object,
                        "analyzer_version": analyzer_version,
                        "justification": justification,
                        "error": error,
                        "message": message,
                        "type": justification_type,
                    },
                )

        else:
            _LOGGER.warning(f"No justifications identified for adviser report: {document_id}")

        return justifications_collected

    @staticmethod
    def create_adviser_results_dataframe_histogram(adviser_type_dataframe: pd.DataFrame) -> pd.DataFrame:
        """Create adviser results dataframe sorted for histogram plot.

        :param adviser_type_dataframe dataframe as given by any of df outputs in `create_adviser_dataframe`
        """
        histogram_data: Dict[str, Any] = {}

        for i in adviser_type_dataframe[["message", "type"]].index:
            message = adviser_type_dataframe[["message", "type"]].loc[i, "message"]

            if message not in histogram_data.keys():
                histogram_data[message] = {
                    "message": message,
                    "type": adviser_type_dataframe[["message", "type"]].loc[i, "type"],
                    "count": adviser_type_dataframe["message"].value_counts()[message],
                }

        sorted_justifications_df = pd.DataFrame(histogram_data)
        sorted_justifications_df = sorted_justifications_df.transpose()
        sorted_justifications_df = sorted_justifications_df.sort_values(by="count", ascending=False)

        return sorted_justifications_df

    @staticmethod
    def _aggregate_data_per_interval(adviser_type_dataframe: pd.DataFrame, number_days: int = 7) -> pd.DataFrame:
        """Aggregate advise justifications per days intervals.

        :param adviser_type_dataframe dataframe produced by `create_adviser_dataframe`
        """
        begin = min(adviser_type_dataframe["date"].values)
        end = max(adviser_type_dataframe["date"].values)

        timestamps = []

        delta = np.timedelta64(number_days, "D")
        intervals = (end - begin) / delta
        value = begin

        for i in range(0, int(intervals) + 1):
            value = value + delta
            timestamps.append(value)

        timestamps[0] = begin
        timestamps[len(timestamps) - 1] = end

        aggregated_data: Dict[str, Any] = {}

        # Iterate over all intervals
        for interval in range(0, len(timestamps)):
            low = timestamps[interval - 1]
            high = timestamps[interval]
            aggregated_data[high] = {}
            subset_df = adviser_type_dataframe[
                (adviser_type_dataframe["date"] >= low) & (adviser_type_dataframe["date"] <= high)
            ]
            messages = pd.unique(subset_df["message"])

            for message in messages:
                if message not in aggregated_data[high].keys():
                    aggregated_data[high][message] = {
                        "message": message,
                        "count": subset_df["message"].value_counts()[message],
                    }
        return aggregated_data

    @staticmethod
    def _create_heatmaps_values(input_data: Dict[str, Any], advise_encoded_type: List[int]) -> Dict[str, Any]:
        """Create values for heatmaps."""
        heatmaps_values: Dict[str, Any] = {}

        for advise_type in set(advise_encoded_type):
            _LOGGER.debug(f"Analyzing advise type... {advise_type}")
            type_values = []

            for upper_interval, interval_runs in input_data.items():
                _LOGGER.debug(f"Checking for that advise type in 'interval'... {upper_interval}")

                if advise_type in interval_runs.keys():
                    type_values.append(interval_runs[advise_type]["count"])
                else:
                    type_values.append(0)

            heatmaps_values[str(advise_type)] = type_values

        return heatmaps_values

    @classmethod
    def create_adviser_results_dataframe_heatmap(
        cls,
        adviser_type_dataframe: pd.DataFrame,
        number_days: int = 7,
    ) -> pd.DataFrame:
        """Create adviser justifications heatmap.

        :param adviser_type_dataframe dataframe as given by any of df outputs in `create_adviser_dataframe`
        :param number_days: number of days to split data.
        """
        data = cls._aggregate_data_per_interval(adviser_type_dataframe=adviser_type_dataframe, number_days=number_days)
        heatmaps_values = cls._create_heatmaps_values(
            input_data=data,
            advise_encoded_type=adviser_type_dataframe["message"].values,
        )
        df_heatmap = pd.DataFrame(heatmaps_values)
        df_heatmap["interval"] = data.keys()
        df_heatmap = df_heatmap.set_index(["interval"])
        df_heatmap = df_heatmap.transpose()

        justifications_ordered = []
        for message in pd.unique(adviser_type_dataframe["message"]):
            justifications_ordered.append(message)

        df_heatmap["advise_type"] = justifications_ordered

        df_heatmap = df_heatmap.set_index(["advise_type"])

        return df_heatmap

    @staticmethod
    def _get_processed_data_prefix(ceph_bucket_prefix: str, processed_data_name: str, environment: str) -> str:
        """Get prefix where processed data are stored."""
        bucket_prefix = ceph_bucket_prefix
        deployment_name = os.environ["THOTH_DEPLOYMENT_NAME"]
        return f"{bucket_prefix}/{deployment_name}/{processed_data_name}-{environment}"

    @classmethod
    def connect_to_ceph(
        cls,
        ceph_bucket_prefix: str,
        processed_data_name: str,
        environment: str,
        bucket: Optional[str] = None,
    ) -> CephStore:
        """Connect to Ceph to store processed data."""
        prefix = cls._get_processed_data_prefix(
            ceph_bucket_prefix=ceph_bucket_prefix,
            processed_data_name=processed_data_name,
            environment=environment,
        )
        ceph = CephStore(prefix=prefix, bucket=bucket)
        ceph.connect()
        return ceph

    @staticmethod
    def store_csv_from_dataframe(
        csv_from_df: str,
        ceph_sli: CephStore,
        file_name: str,
        ceph_path: str,
        is_public: bool = False,
    ) -> None:
        """Store CSV obtained from pd.DataFrame on Ceph.

        param: csv_from_df: CSV given from pd.DataFrame.to_csv()
        """
        if is_public:
            _LOGGER.info(f"Storing on public bucket... {ceph_path}")
        else:
            _LOGGER.info(f"Storing on private bucket... {ceph_path}")
        ceph_sli.store_blob(blob=csv_from_df, object_key=ceph_path)
        _LOGGER.info(f"Succesfully stored  {file_name} at {ceph_path}")

    @staticmethod
    def create_pretty_report_from_json(report: Dict[str, Any], is_justification: bool = False) -> str:
        """Create Markdown output from adviser report input."""
        md_report_complete = ""
        if not report:
            return md_report_complete

        products = report.get("products")
        if not products:
            return md_report_complete

        md_report_complete = "Report"

        md_report_complete += "\n\n" + "Justifications"

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

        md_report_complete += "\n\n" + final_df.to_markdown()

        if is_justification:
            return md_report_complete

        # Packages in Advised Pipfile
        md_report_complete += Adviser._add_packages_in_advised_pipfile_to_md_report(product=product, is_dev=False)

        # Dev-Packages in Advised Pipfile
        md_report_complete += Adviser._add_packages_in_advised_pipfile_to_md_report(product=product, is_dev=True)

        requirements = product["project"]["requirements"]

        if "requires" in requirements:
            if requirements["requires"]:
                md_report_complete += "\n\n" + "Requires in Advised Pipfile"
                df = pd.DataFrame([requirements["requires"]])
                md_report_complete += "\n\n" + df.to_markdown()

        if "source" in requirements:
            if requirements["source"]:
                md_report_complete += "\n\n" + "Source in Advised Pipfile"
                df = pd.DataFrame(requirements["source"])
                md_report_complete += "\n\n" + df.to_markdown()

        # Packages in Advised Pipfile.lock
        md_report_complete += Adviser._add_packages_in_advised_pipfile_lock_to_md_report(product=product, is_dev=False)

        # Dev-Packages in Advised Pipfile.lock
        md_report_complete += Adviser._add_packages_in_advised_pipfile_lock_to_md_report(product=product, is_dev=True)

        # Runtime Environment
        md_report_complete += Adviser._add_runtime_environment_to_md_report(product=product)

        if "score" in product:
            if product["score"]:
                md_report_complete += "\n\n" + "Software Stack Score"
                df = pd.DataFrame([{"score": product["score"]}])
                md_report_complete += "\n\n" + df.to_markdown()

        return md_report_complete

    @staticmethod
    def _add_packages_in_advised_pipfile_to_md_report(product: Dict[str, Any], is_dev: bool) -> str:
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
    def _add_packages_in_advised_pipfile_lock_to_md_report(product: Dict[str, Any], is_dev: bool) -> str:
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
    def _add_runtime_environment_to_md_report(product: Dict[str, Any]) -> str:
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
