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
import hashlib
import copy

from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

import pandas as pd
import numpy as np
from numpy import array
from sklearn.preprocessing import LabelEncoder

from thoth.report_processing.exceptions import ThothMissingDatasetAtPath

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
        cls, limit_results: bool = False, max_ids: int = 5, is_local: bool = False, repo_path: Optional[Path] = None
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

        if not is_local:
            files, counter = cls._aggregate_thoth_results_from_ceph(
                files=files, limit_results=limit_results, max_ids=max_ids
            )
            _LOGGER.info("Number of files retrieved is: %r" % counter)

            return files

        files, counter = cls._aggregate_thoth_results_from_local(
            repo_path=repo_path, files=files, limit_results=limit_results, max_ids=max_ids
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
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from local repo."""
        _LOGGER.info(f"Retrieving dataset at path... {repo_path}")
        if not repo_path:
            _LOGGER.warning(f"No Path has been provided to retrieve data locally.")
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
        files: Dict[str, Any], store_files: Optional[List[str]] = None, limit_results: bool = False, max_ids: int = 5
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from Ceph."""
        adviser_store = AdvisersResultsStore()
        adviser_store.connect()

        adviser_ids = list(adviser_store.get_document_listing())

        _LOGGER.info("Number of Adviser reports identified is: %r" % len(adviser_ids))

        number_adviser_results = len(adviser_ids)

        counter = 0

        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids} to test functions!!")

        for n, document_id in enumerate(adviser_ids):
            _LOGGER.debug(f"Analysis {document_id} n.{counter + 1}/{number_adviser_results}")

            try:
                document = adviser_store.retrieve_document(document_id)
                files[document_id] = document

                counter += 1

                _LOGGER.info("Documents retrieved: %r", counter)

                if limit_results:
                    if counter == max_ids:
                        return files, counter

            except Exception as exception:
                _LOGGER.exception(f"Exception during retrieval of adviser result {document_id}: {exception}")
                continue

        return files, counter

    @classmethod
    def create_adviser_dataframe(cls, adviser_version: str, adviser_files: Dict[str, Any]) -> pd.DataFrame:
        """Create adviser dataframe.

        :param adviser_version: adviser version filter
        :param adviser_files: adviser documents
        """
        adviser_dict = {}
        _LOGGER.warning(f"Considering adviser version: {adviser_version}")

        for document_id, document in adviser_files.items():
            datetime_advise_run = document["metadata"].get("datetime")
            analyzer_version = document["metadata"].get("analyzer_version")

            result = document["result"]

            if str(analyzer_version) == str(adviser_version):

                report = result.get("report")
                error = result["error"]

                if error:
                    error_msg = result["error_msg"]
                    adviser_dict[document_id] = {
                        "justification": [{"message": error_msg, "type": "ERROR"}],
                        "error": error,
                        "message": error_msg,
                        "type": "ERROR",
                    }
                else:
                    adviser_dict = cls.extract_adviser_justifications(
                        report=report, adviser_dict=adviser_dict, document_id=document_id
                    )

            if document_id in adviser_dict.keys():
                adviser_dict[document_id]["datetime"] = datetime.strptime(datetime_advise_run, "%Y-%m-%dT%H:%M:%S.%f")
                adviser_dict[document_id]["analyzer_version"] = analyzer_version

        return cls._create_adviser_dataframe(adviser_dict)

    @staticmethod
    def _create_adviser_dataframe(adviser_data: Dict[str, Any]) -> pd.DataFrame:
        """Create dataframe of adviser results from data collected."""
        adviser_df = pd.DataFrame(
            adviser_data, index=["datetime", "analyzer_version", "error", "justification", "message", "type"]
        )
        adviser_df = adviser_df.transpose()
        adviser_df["date"] = pd.to_datetime(adviser_df["datetime"])

        return adviser_df

    @classmethod
    def extract_adviser_justifications(
        cls, report: Optional[Dict[str, Any]], adviser_dict: Dict[str, Any], document_id: str
    ) -> Dict[str, Any]:
        """Retrieve justifications from adviser document."""
        if not report:
            _LOGGER.warning(f"No report identified in adviser document: {document_id}")
            return adviser_dict

        products = report.get("products")
        adviser_dict = cls.extract_justifications_from_products(
            products=products, adviser_dict=adviser_dict, document_id=document_id
        )

        return adviser_dict

    @staticmethod
    def extract_justifications_from_products(
        products: Optional[List[Dict[str, Any]]], adviser_dict: Dict[str, Any], document_id: str
    ) -> Dict[str, Any]:
        """Extract justifications from products in adviser document."""
        if not products:
            _LOGGER.warning(f"No products identified in adviser document: {document_id}")
            return adviser_dict

        for product in products:
            justifications = product["justification"]

            if justifications:
                # Collect all justifications
                for justification in justifications:
                    if "advisory" in justification:
                        adviser_dict[document_id] = {
                            "justification": justification,
                            "error": True,
                            "message": justification["advisory"],
                            "type": "INFO",
                        }
                    else:
                        adviser_dict[document_id] = {
                            "justification": justification,
                            "error": False,
                            "message": justification["message"],
                            "type": justification["type"],
                        }
            else:
                _LOGGER.warning(f"No justifications identified for adviser report: {document_id}")

        return adviser_dict

    @staticmethod
    def create_summary_dataframe(adviser_dataframe: pd.DataFrame) -> pd.DataFrame:
        """Create summary dataframe with all information required for visualization or storage.

        :param adviser_dataframe: DataFrame as returned by `create_adviser_dataframe` method.
        """
        jm_encoding = []
        for index, row in adviser_dataframe[["message"]].iterrows():
            hash_object = hashlib.sha256(bytes(row.values[0], "raw_unicode_escape"))
            hex_dig = hash_object.hexdigest()
            jm_encoding.append([index, row.values, hex_dig])

        label_encoder = LabelEncoder()
        justification_result = copy.deepcopy(adviser_dataframe.to_dict())

        jm_hash_id_values = [hex_digits[2] for hex_digits in jm_encoding]
        integer_jm_hash_id_values_encoded = label_encoder.fit_transform(array(jm_hash_id_values))

        counter = 0
        for jm_id in integer_jm_hash_id_values_encoded:
            jm_encoding[counter] = jm_encoding[counter] + [jm_id]
            counter += 1

        justification_result["jm_hash_id_encoded"] = {el[0]: el[3] for el in jm_encoding}

        total_dataframe = pd.DataFrame(justification_result)

        return total_dataframe

    @staticmethod
    def create_adviser_results_dataframe_histogram(adviser_type_dataframe: pd.DataFrame) -> pd.DataFrame:
        """Create adviser results dataframe sorted for histogram plot.

        :param adviser_type_dataframe dataframe as given by any of df outputs in `create_summary_dataframe`
        """
        histogram_data: Dict[str, Any] = {}

        for index, row in adviser_type_dataframe[["jm_hash_id_encoded", "message", "type"]].iterrows():
            encoded_id = row["jm_hash_id_encoded"]
            if encoded_id not in histogram_data.keys():
                histogram_data[encoded_id] = {
                    "jm_hash_id_encoded": f"type-{encoded_id}",
                    "message": row["message"],
                    "type": row["type"],
                    "count": adviser_type_dataframe["jm_hash_id_encoded"].value_counts()[encoded_id],
                }

        sorted_justifications_df = pd.DataFrame(histogram_data)
        sorted_justifications_df = sorted_justifications_df.transpose()
        sorted_justifications_df = sorted_justifications_df.sort_values(by="count", ascending=False)

        return sorted_justifications_df

    @staticmethod
    def _aggregate_data_per_interval(adviser_type_dataframe: pd.DataFrame, number_days: int = 7) -> pd.DataFrame:
        """Aggregate advise justifications per days intervals.

        :param adviser_type_dataframe dataframe produced by `create_summary_dataframe`
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

        for l in range(0, len(timestamps)):
            low = timestamps[l - 1]
            high = timestamps[l]
            aggregated_data[high] = {}
            subset_df = adviser_type_dataframe[
                (adviser_type_dataframe["date"] >= low) & (adviser_type_dataframe["date"] <= high)
            ]

            for index, row in subset_df[["jm_hash_id_encoded", "message", "date"]].iterrows():
                encoded_id = row["jm_hash_id_encoded"]
                if encoded_id not in aggregated_data[high].keys():
                    aggregated_data[high][encoded_id] = {
                        "jm_hash_id_encoded": f"type-{encoded_id}",
                        "message": row["message"],
                        "count": subset_df["jm_hash_id_encoded"].value_counts()[encoded_id],
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
        cls, adviser_type_dataframe: pd.DataFrame, number_days: int = 7
    ) -> pd.DataFrame:
        """Create adviser justifications heatmap.

        :param adviser_type_dataframe dataframe as given by any of df outputs in `create_summary_dataframe`
        :param number_days: number of days to split data.
        """
        data = cls._aggregate_data_per_interval(adviser_type_dataframe=adviser_type_dataframe, number_days=number_days)
        heatmaps_values = cls._create_heatmaps_values(
            input_data=data, advise_encoded_type=adviser_type_dataframe["jm_hash_id_encoded"].values
        )
        df_heatmap = pd.DataFrame(heatmaps_values)
        df_heatmap["interval"] = data.keys()
        df_heatmap = df_heatmap.set_index(["interval"])
        df_heatmap = df_heatmap.transpose()

        adviser_justifications_map: Dict[str, Any] = {}
        for index, row in adviser_type_dataframe[["jm_hash_id_encoded", "message"]].iterrows():
            if row["jm_hash_id_encoded"] not in adviser_justifications_map.keys():
                adviser_justifications_map[str(row["jm_hash_id_encoded"])] = row["message"]

        justifications_ordered = []
        for index, row in df_heatmap.iterrows():

            justifications_ordered.append(adviser_justifications_map[index])

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
        cls, ceph_bucket_prefix: str, processed_data_name: str, environment: str, bucket: Optional[str] = None
    ) -> CephStore:
        """Connect to Ceph to store processed data."""
        prefix = cls._get_processed_data_prefix(
            ceph_bucket_prefix=ceph_bucket_prefix, processed_data_name=processed_data_name, environment=environment
        )
        ceph = CephStore(prefix=prefix, bucket=bucket)
        ceph.connect()
        return ceph

    @staticmethod
    def store_csv_from_dataframe(
        csv_from_df: str, ceph_sli: CephStore, file_name: str, ceph_path: str, is_public: bool = False
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
