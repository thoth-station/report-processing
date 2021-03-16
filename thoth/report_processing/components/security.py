#!/usr/bin/env python3
# thoth-report-processing
# Copyright(C) 2020 Francesco Murdaca
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

"""Security Indicators reports processing methods."""

import os
import logging
import json

from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Union

import pandas as pd

from thoth.report_processing.exceptions import ThothSIPackageNotMatchingException
from thoth.report_processing.exceptions import ThothNotKnownResultStore
from thoth.report_processing.exceptions import ThothMissingDatasetAtPath
from thoth.report_processing.enums import ThothSecurityIndicatorsFileStoreEnum

from thoth.storages.security_indicators import SecurityIndicatorsResultsStore
from thoth.storages.security_indicators import SIAggregatedStore, SIClocStore, SIBanditStore

# set up logging
DEBUG_LEVEL = bool(int(os.getenv("DEBUG_LEVEL", 0)))

if DEBUG_LEVEL:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

_LOGGER = logging.getLogger(__name__)


class _SecurityIndicators:
    """Class of methods used to process reports from Security Indicators (SI) analyzer."""

    RESULTS_STORE = SecurityIndicatorsResultsStore

    def aggregate_thoth_security_indicators_results(
        self,
        store_files: Optional[List[str]] = None,
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = False,
        repo_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Aggregate results stored on Ceph or locally from repo for Thoth components reports.

        :param store_files: files to be retrieved from the Store for each result, if None all files are retrieved.
        :param limit_results: reduce the number of reports ids considered to `max_ids`.
        :param max_ids: maximum number of reports ids considered.
        :param is_local: flag to retrieve the dataset locally (if not uses Ceph S3 (credentials are required)).
        :param repo_path: required if you want to retrieve the dataset locally and `is_local` is set to True.
        """
        if store_files:
            if any(store_file not in ThothSecurityIndicatorsFileStoreEnum.__members__ for store_file in store_files):
                raise ThothNotKnownResultStore(
                    f"SecurityIndicatorsStore does not contain some of the files listed: {store_files}. \
                        \nSecurityIndicatorsStore: {ThothSecurityIndicatorsFileStoreEnum.__members__.keys()}",
                )

        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids}!")

        files: Dict[str, Any] = {}

        if is_local:
            files, counter = self._aggregate_thoth_results_from_local(
                repo_path=repo_path,
                files=files,
                limit_results=limit_results,
                max_ids=max_ids,
                store_files=store_files,
            )

        else:
            files, counter = self._aggregate_thoth_results_from_ceph(
                store_files=store_files,
                files=files,
                limit_results=limit_results,
                max_ids=max_ids,
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
            _LOGGER.warning("No Path has been provided to retrieve data locally.")
            return files, 0

        if not repo_path.exists():
            raise ThothMissingDatasetAtPath(f"There is no dataset at this path: {repo_path}.")

        counter = 0

        for result_path in repo_path.iterdir():
            _LOGGER.info(f"Considering... {result_path}")

            if "security-indicator" not in result_path.name:
                raise Exception(f"This repo is not part of security-indicator! {result_path}")

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
        store_class_type = self.RESULTS_STORE

        counter = 0

        files_id = []
        for security_indicator_key in store_class_type.iter_security_indicators():
            security_indicator_id = security_indicator_key.split("/")[0]

            if security_indicator_id not in files_id:
                _LOGGER.info(f"Document id: {security_indicator_id}")

                files_id.append(security_indicator_id)

                try:
                    retrieved_files: Dict[str, Any] = {security_indicator_id: {}}

                    if store_files and ThothSecurityIndicatorsFileStoreEnum.bandit.name in store_files:
                        si_bandit_store = SIBanditStore(security_indicator_id=security_indicator_id)
                        si_bandit_store.connect()

                        si_bandit_report = si_bandit_store.retrieve_document()
                        retrieved_files[security_indicator_id][
                            ThothSecurityIndicatorsFileStoreEnum.bandit.name
                        ] = si_bandit_report

                    if store_files and ThothSecurityIndicatorsFileStoreEnum.cloc.name in store_files:
                        si_cloc_store = SIClocStore(security_indicator_id=security_indicator_id)
                        si_cloc_store.connect()

                        si_cloc_report = si_cloc_store.retrieve_document()
                        retrieved_files[security_indicator_id][
                            ThothSecurityIndicatorsFileStoreEnum.cloc.name
                        ] = si_cloc_report

                    if store_files and ThothSecurityIndicatorsFileStoreEnum.aggregated.name in store_files:
                        si_aggregated_store = SIAggregatedStore(security_indicator_id=security_indicator_id)
                        si_aggregated_store.connect()

                        si_aggregated_report = si_aggregated_store.retrieve_document()
                        retrieved_files[security_indicator_id][
                            ThothSecurityIndicatorsFileStoreEnum.aggregated.name
                        ] = si_aggregated_report

                    files[security_indicator_id] = retrieved_files[security_indicator_id]

                    counter += 1

                    _LOGGER.info("Documents retrieved: %r", counter)

                    if limit_results:
                        if counter == max_ids:
                            return files, counter
                except Exception as si_exception:
                    _LOGGER.exception(
                        f"Exception during retrieval of SI result {security_indicator_id}: {si_exception}",
                    )
                    pass

        return files, counter


class SecurityIndicatorsBandit(_SecurityIndicators):
    """Class of methods used to process reports from Security Indicators (SI) bandit analyzer."""

    # Weights for Confidence
    HIGH_CONFIDENCE_WEIGHT = 1
    MEDIUM_CONFIDENCE_WEIGHT = 0.5
    LOW_CONFIDENCE_WEIGHT = 0.1

    # Weights for Security
    HIGH_SEVERITY_WEIGHT = 100
    MEDIUM_SEVERITY_WEIGHT = 10
    LOW_SEVERITY_WEIGHT = 1

    @staticmethod
    def aggregate_security_indicator_bandit_results(
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = False,
        security_indicator_bandit_repo_path: Path = Path("security-indicators"),
    ) -> List[Any]:
        """Aggregate si_bandit results from Ceph or locally using the provided path.

        :param limit_results: reduce the number of si_bandit reports ids considered to `max_ids` to test analysis.
        :param max_ids: maximum number of si_bandit reports ids considered.
        :param is_local: flag to retreive the dataset locally or from S3 (credentials are required).
        :param si_bandit_repo_path: path to retrieve the si_bandit dataset locally and `is_local` is set to True.
        """
        document_name = "bandit"
        si_reports: Dict[str, Any] = _SecurityIndicators().aggregate_thoth_security_indicators_results(
            store_files=[document_name],
            limit_results=limit_results,
            max_ids=max_ids,
            is_local=is_local,
            repo_path=security_indicator_bandit_repo_path,
        )
        security_indicator_bandit_reports = [
            document_results[document_name]
            for document_id, document_results in si_reports.items()
            if document_name in document_results
        ]

        _LOGGER.info("Number of files that can be used is: %r" % len(security_indicator_bandit_reports))

        return security_indicator_bandit_reports

    @staticmethod
    def _extract_data_from_si_bandit_metadata(si_bandit_report: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data from si-bandit report metadata.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.

        :output extracted_metadata: dictinary with metadata retrieved from SI bandit report.
        """
        report_metadata = si_bandit_report["metadata"]

        extracted_metadata = {
            "datetime_si_bandit": report_metadata["datetime"],
            "analyzer_si_bandit": report_metadata["analyzer"],
            "analyzer_version_si_bandit": report_metadata["analyzer_version"],
            "document_id_si_bandit": report_metadata["document_id"],
            "package_name": report_metadata["arguments"]["si-bandit"]["package_name"],
            "package_version": report_metadata["arguments"]["si-bandit"]["package_version"],
            "package_index": report_metadata["arguments"]["si-bandit"]["package_index"],
        }

        return extracted_metadata

    def create_si_bandit_metadata_dataframe(
        self,
        si_bandit_report: Dict[str, Any],
        analyzer_version: Optional[str] = None,
    ) -> pd.DataFrame:
        """Create si-bandit report metadata dataframe.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param analyzer_version: analyzer version filter

        :output metadata_df: pandas.DataFrame with metadata obtained from `extract_data_from_si_bandit_metadata`.
        """
        if analyzer_version:
            document_id = si_bandit_report["metadata"]["document_id"]
            version = si_bandit_report["metadata"]["analyzer_version"]

            if not int("".join(version.split("."))) >= int("".join(analyzer_version.split("."))):
                _LOGGER.info(f"Skipping SI-bandit report: {document_id} because has version: {version}")
                return pd.DataFrame()

        metadata_si_bandit = self._extract_data_from_si_bandit_metadata(si_bandit_report=si_bandit_report)
        metadata_df = pd.DataFrame([metadata_si_bandit])

        return metadata_df

    @staticmethod
    def extract_severity_confidence_info(
        si_bandit_report: Dict[str, Any],
        filters_files: Optional[List[str]] = None,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """Extract severity and confidence from result metrics.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.

        :output extracted_info: list of dictionary for each SEVERITY/CONFIDENCE combination.
        :output summary_files: dictionary with statistics about analyzed, filtered total files.
        """
        extracted_info: List[Dict[str, Any]] = []

        summary_files = {
            "number_of_analyzed_files": 0,
            "number_of_files_with_severities": 0,
            "number_of_filtered_files": 0,
        }

        if not filters_files:
            filters_files = []

        si_bandit_result = si_bandit_report["result"]

        si_bandit_report_result_metrics_df = pd.DataFrame(si_bandit_result["metrics"])
        si_bandit_report_result_results_df = pd.DataFrame(si_bandit_result["results"])

        if "filename" not in si_bandit_report_result_results_df.columns.values:
            return extracted_info, summary_files

        for file in si_bandit_report_result_metrics_df.columns.values:
            # Filter tests/ file
            if file != "_totals" and not any(filter_ in file for filter_ in filters_files):

                analysis = {}
                analysis["name"] = file

                analysis["SEVERITY.LOW"] = {
                    "CONFIDENCE.LOW": 0,
                    "CONFIDENCE.MEDIUM": 0,
                    "CONFIDENCE.HIGH": 0,
                    "CONFIDENCE.UNDEFINED": 0,
                }
                analysis["SEVERITY.MEDIUM"] = {
                    "CONFIDENCE.LOW": 0,
                    "CONFIDENCE.MEDIUM": 0,
                    "CONFIDENCE.HIGH": 0,
                    "CONFIDENCE.UNDEFINED": 0,
                }
                analysis["SEVERITY.HIGH"] = {
                    "CONFIDENCE.LOW": 0,
                    "CONFIDENCE.MEDIUM": 0,
                    "CONFIDENCE.HIGH": 0,
                    "CONFIDENCE.UNDEFINED": 0,
                }

                subset_df = si_bandit_report_result_results_df[
                    si_bandit_report_result_results_df["filename"].values == file
                ]
                if subset_df.shape[0] > 0:
                    # check if there are severities for the file

                    for index, row in subset_df[["issue_confidence", "issue_severity"]].iterrows():
                        analysis[f"SEVERITY.{row['issue_confidence']}"][f"CONFIDENCE.{row['issue_severity']}"] += 1

                    summary_files["number_of_files_with_severities"] += 1

                summary_files["number_of_analyzed_files"] += 1

                extracted_info.append(analysis)

            elif file != "_totals" and any(filter_ in file for filter_ in filters_files):
                summary_files["number_of_filtered_files"] += 1

        return extracted_info, summary_files

    def create_security_confidence_dataframe(
        self,
        si_bandit_report: Dict[str, Any],
        filters_files: Optional[List[str]] = None,
    ) -> Tuple[pd.DataFrame, Dict[str, int]]:
        """Create Security/Confidence dataframe for si-bandit report.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.

        :output sec_conf_df: pandas.DataFrame with all info about SEVERITY/CONFIDENCE for the package analyzed.
        :output summary_files: dictionary with statistics about analyzed, filtered total files.
        """
        results_sec_conf, summary_files = self.extract_severity_confidence_info(
            si_bandit_report=si_bandit_report,
            filters_files=filters_files,
        )

        summary_df = pd.DataFrame()

        if results_sec_conf:
            summary_df = pd.json_normalize(results_sec_conf, sep="__").set_index("name")
        else:
            summary_df = pd.json_normalize(results_sec_conf, sep="__")

        summary_df["_total_severity"] = summary_df.sum(axis=1)
        sec_conf_df = summary_df.transpose()
        sec_conf_df["_total"] = sec_conf_df.sum(axis=1)

        return sec_conf_df, summary_files

    @staticmethod
    def produce_si_bandit_report_summary_dataframe(
        metadata_df: pd.DataFrame,
        si_bandit_sec_conf_df: pd.DataFrame,
        summary_files: Dict[str, int],
    ) -> pd.DataFrame:
        """Create si-bandit report summary dataframe.

        :param metadata_df: pandas.DataFrame provided by `create_si_bandit_metadata_dataframe`.
        :param sec_conf_df: pandas.DataFrame provided by `create_security_confidence_dataframe`.
        :output summary_files: dictionary with statistics about analyzed, filtered total files.

        :output report_summary_df: pandas.DataFrame summary for a single si bandit report.
        """
        subset_df = pd.DataFrame([si_bandit_sec_conf_df["_total"].to_dict()])
        report_summary_df = pd.concat([metadata_df, subset_df], axis=1)
        report_summary_df["number_of_files_with_severities"] = pd.to_numeric(
            summary_files["number_of_files_with_severities"],
        )
        report_summary_df["number_of_analyzed_files"] = pd.to_numeric(summary_files["number_of_analyzed_files"])
        report_summary_df["number_of_filtered_files"] = pd.to_numeric(summary_files["number_of_filtered_files"])
        report_summary_df["number_of_files_total"] = (
            pd.to_numeric(
                summary_files["number_of_filtered_files"],
            )
            + pd.to_numeric(summary_files["number_of_analyzed_files"])
        )
        report_summary_df["_total_severity"] = pd.to_numeric(report_summary_df["_total_severity"])

        return report_summary_df

    def create_si_bandit_final_dataframe(
        self,
        si_bandit_report: Dict[str, Any],
        filters_files: Optional[List[str]] = None,
        analyzer_version: Optional[str] = None,
    ) -> pd.DataFrame:
        """Create final si-bandit dataframe.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.
        :param analyzer_version: analyzer version filter

        :output report_summary_df: pandas.DataFrame summary for a single si bandit report.
        """
        if analyzer_version:
            document_id = si_bandit_report["metadata"]["document_id"]
            version = si_bandit_report["metadata"]["analyzer_version"]

            if not int("".join(version.split("."))) >= int("".join(analyzer_version.split("."))):
                _LOGGER.info(f"Skipping SI-bandit report: {document_id} because has version: {version}")
                return pd.DataFrame()

        # Create metadata dataframe
        metadata_df = self.create_si_bandit_metadata_dataframe(
            si_bandit_report=si_bandit_report,
            analyzer_version=analyzer_version,
        )

        if analyzer_version and metadata_df.empty:
            _LOGGER.info(f"Skipping SI-bandit report: {document_id} because has version: {version}")
            return pd.DataFrame()

        # Create metadata dataframe
        package_name = metadata_df["package_name"][0]
        package_version = metadata_df["package_version"][0]
        package_index = metadata_df["package_index"][0]

        _LOGGER.info(f"Analyzing si_bandit report for package_name: {package_name}")
        _LOGGER.info(f"Analyzing si_bandit report for package_version: {package_version}")
        _LOGGER.info(f"Analyzing si_bandit report for package_index: {package_index}")

        # Create Security/Confidence dataframe
        security_confidence_df, summary_files = self.create_security_confidence_dataframe(
            si_bandit_report=si_bandit_report,
            filters_files=filters_files,
        )

        # Create Summary dataframe
        si_bandit_report_summary_df = self.produce_si_bandit_report_summary_dataframe(
            metadata_df=metadata_df,
            si_bandit_sec_conf_df=security_confidence_df,
            summary_files=summary_files,
        )

        return si_bandit_report_summary_df

    def aggregate_si_bandit_final_dataframe(
        self,
        si_bandit_reports: List[Dict[str, Any]],
        filters_files: Optional[List[str]] = None,
        analyzer_version: Optional[str] = None,
    ) -> pd.DataFrame:
        """Aggregate si-bandit dataframes into final dataframe.

        :param si_bandit_reports: list of SI bandit report provided by Thoth SI bandit analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.
        :param analyzer_version: analyzer version filter

        :output final_df: pandas.DataFrame aggregating all SI bandit reports provided.
        """
        counter = 1
        final_df = pd.DataFrame()
        total_reports = len(si_bandit_reports)

        for si_bandit_report in si_bandit_reports:

            document_id = si_bandit_report["metadata"]["document_id"]
            _LOGGER.info(f"Analyzing SI-bandit report: {counter}/{total_reports}")

            si_bandit_report_summary_df = self.create_si_bandit_final_dataframe(
                si_bandit_report=si_bandit_report,
                filters_files=filters_files,
                analyzer_version=analyzer_version,
            )
            if not si_bandit_report_summary_df.empty:
                final_df = pd.concat([final_df, si_bandit_report_summary_df], axis=0)

                counter += 1
            else:
                _LOGGER.info(f"Skipping SI-bandit report: {document_id} because has different version")

        final_df.reset_index(inplace=True, drop=True)

        return final_df

    def create_security_indicators_scores(self, si_bandit_df: pd.DataFrame) -> pd.DataFrame:
        """Create Security Indicators (SI) scores from si bandit outputs.

        :param si_bandit_df: pandas.DataFrame as given by `aggregate_si_bandit_final_dataframe`.

        :output si_bandit_df: Extend `si_bandit_df` with SI scores created using all rows (aka all packages).
        """
        if not any("SEVERITY" in column for column in si_bandit_df.columns):
            si_bandit_df["SEVERITY.score"] = 0
            si_bandit_df["SEVERITY.score.normalized"] = 0
            _LOGGER.exception("All reports considered have no vulnerabilities")
            return si_bandit_df

        for security in ["LOW", "MEDIUM", "HIGH"]:
            for confidence in ["LOW", "MEDIUM", "HIGH"]:

                vulnerability_class = f"SEVERITY.{security}__CONFIDENCE.{confidence}"

                min_max_scaler = (si_bandit_df[vulnerability_class] - si_bandit_df[vulnerability_class].min()) / (
                    si_bandit_df[vulnerability_class].max() - si_bandit_df[vulnerability_class].min()
                )

                si_bandit_df[f"{vulnerability_class}_scaled"] = min_max_scaler

        si_bandit_df["SEVERITY.HIGH.sub_score"] = (
            si_bandit_df["SEVERITY.HIGH__CONFIDENCE.HIGH_scaled"].fillna(0) * self.HIGH_CONFIDENCE_WEIGHT
            + si_bandit_df["SEVERITY.HIGH__CONFIDENCE.MEDIUM_scaled"].fillna(0) * self.MEDIUM_CONFIDENCE_WEIGHT
            + si_bandit_df["SEVERITY.HIGH__CONFIDENCE.LOW_scaled"].fillna(0) * self.LOW_CONFIDENCE_WEIGHT
        ) / 3

        si_bandit_df["SEVERITY.MEDIUM.sub_score"] = (
            si_bandit_df["SEVERITY.MEDIUM__CONFIDENCE.HIGH_scaled"].fillna(0) * self.HIGH_CONFIDENCE_WEIGHT
            + si_bandit_df["SEVERITY.MEDIUM__CONFIDENCE.MEDIUM_scaled"].fillna(0) * self.MEDIUM_CONFIDENCE_WEIGHT
            + si_bandit_df["SEVERITY.MEDIUM__CONFIDENCE.LOW_scaled"].fillna(0) * self.LOW_CONFIDENCE_WEIGHT
        ) / 3

        si_bandit_df["SEVERITY.LOW.sub_score"] = (
            si_bandit_df["SEVERITY.LOW__CONFIDENCE.HIGH_scaled"].fillna(0) * self.HIGH_CONFIDENCE_WEIGHT
            + si_bandit_df["SEVERITY.LOW__CONFIDENCE.MEDIUM_scaled"].fillna(0) * self.MEDIUM_CONFIDENCE_WEIGHT
            + si_bandit_df["SEVERITY.LOW__CONFIDENCE.LOW_scaled"].fillna(0) * self.LOW_CONFIDENCE_WEIGHT
        ) / 3

        si_bandit_df["SEVERITY.score"] = (
            si_bandit_df["SEVERITY.HIGH.sub_score"] * self.HIGH_SEVERITY_WEIGHT
            + si_bandit_df["SEVERITY.MEDIUM.sub_score"] * self.MEDIUM_SEVERITY_WEIGHT
            + si_bandit_df["SEVERITY.LOW.sub_score"] * self.LOW_SEVERITY_WEIGHT
        ) / 3

        si_bandit_df["SEVERITY.score.normalized"] = (
            si_bandit_df["SEVERITY.score"] / si_bandit_df["number_of_analyzed_files"].max()
        )

        return si_bandit_df


class SecurityIndicatorsCloc:
    """Class of methods used to process reports from Security Indicators (SI) cloc analyzer."""

    @staticmethod
    def aggregate_security_indicator_cloc_results(
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = False,
        security_indicator_cloc_repo_path: Path = Path("security-indicators"),
    ) -> List[Any]:
        """Aggregate si_cloc results from Ceph or locally using the provided path.

        :param limit_results: reduce the number of si_cloc reports ids considered to `max_ids` to test analysis
        :param max_ids: maximum number of si_cloc reports ids considered
        :param is_local: flag to retreive the dataset locally or from S3 (credentials are required)
        :param si_cloc_repo_path: path to retrieve the si_cloc dataset locally and `is_local` is set to True
        """
        document_name = "cloc"

        si_reports: Dict[str, Any] = _SecurityIndicators().aggregate_thoth_security_indicators_results(
            store_files=[document_name],
            limit_results=limit_results,
            max_ids=max_ids,
            is_local=is_local,
            repo_path=security_indicator_cloc_repo_path,
        )
        security_indicator_cloc_reports = [
            document_results[document_name]
            for document_id, document_results in si_reports.items()
            if document_name in document_results
        ]

        _LOGGER.info("Number of files that can be used is: %r" % len(security_indicator_cloc_reports))

        return security_indicator_cloc_reports

    @staticmethod
    def _extract_data_from_si_cloc_metadata(si_cloc_report: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data from si-cloc report metadata.

        :param si_cloc_report: SI cloc report provided by Thoth SI cloc analyzer.
        :output extracted_metadata: dictinary with metadata retrieved from SI cloc report.
        """
        report_metadata = si_cloc_report["metadata"]

        extracted_metadata = {
            "datetime_si_cloc": report_metadata["datetime"],
            "analyzer_si_cloc": report_metadata["analyzer"],
            "analyzer_version_si_cloc": report_metadata["analyzer_version"],
            "document_id_si_cloc": report_metadata["document_id"],
            "package_name": report_metadata["arguments"]["si-cloc"]["package_name"],
            "package_version": report_metadata["arguments"]["si-cloc"]["package_version"],
            "package_index": report_metadata["arguments"]["si-cloc"]["package_index"],
        }

        return extracted_metadata

    def create_si_cloc_metadata_dataframe(
        self,
        si_cloc_report: Dict[str, Any],
        analyzer_version: Optional[str] = None,
    ) -> pd.DataFrame:
        """Create si-cloc report metadata dataframe.

        :param si_cloc_report: SI cloc report provided by Thoth SI cloc analyzer.
        :param analyzer_version: analyzer version filter

        :output metadata_df: pandas.DataFrame with metadata obtained from `extract_data_from_si_cloc_metadata`.
        """
        if analyzer_version:
            document_id = si_cloc_report["metadata"]["document_id"]
            version = si_cloc_report["metadata"]["analyzer_version"]

            if not int("".join(version.split("."))) >= int("".join(analyzer_version.split("."))):
                _LOGGER.info(f"Skipping SI-cloc report: {document_id} because has version: {version}")
                return pd.DataFrame()

        metadata_si_cloc = self._extract_data_from_si_cloc_metadata(si_cloc_report=si_cloc_report)
        metadata_df = pd.DataFrame([metadata_si_cloc])

        return metadata_df

    def create_si_cloc_results_dataframe(self, si_cloc_report: Dict[str, Any]) -> pd.DataFrame:
        """Create si-cloc report results dataframe."""
        results = {k: v for k, v in si_cloc_report["result"].items() if k != "header"}
        results["SUM"]["n_lines"] = si_cloc_report["result"]["header"]["n_lines"]
        results_df = pd.json_normalize(results)

        return results_df

    @staticmethod
    def produce_si_cloc_report_summary_dataframe(
        metadata_df: pd.DataFrame,
        cloc_results_df: pd.DataFrame,
    ) -> pd.DataFrame:
        """Create si-cloc report summary dataframe.

        :param metadata_df: pandas.DataFrame provided by `create_si_cloc_metadata_dataframe`.
        :param cloc_results_df: pandas.DataFrame provided by `create_si_cloc_results_dataframe`.

        :output report_summary_df: pandas.DataFrame summary for a single si cloc report.
        """
        report_summary_df = pd.concat([metadata_df, cloc_results_df], axis=1)

        return report_summary_df

    def create_si_cloc_final_dataframe(
        self,
        si_cloc_report: Dict[str, Any],
        analyzer_version: Optional[str] = None,
    ) -> pd.DataFrame:
        """Create final si-cloc final dataframe.

        :param si_cloc_report: SI cloc report provided by Thoth SI cloc analyzer.
        :param analyzer_version: analyzer version filter

        :output report_summary_df: pandas.DataFrame summary for a single si cloc report.
        """
        if analyzer_version:
            document_id = si_cloc_report["metadata"]["document_id"]
            version = si_cloc_report["metadata"]["analyzer_version"]

            if not int("".join(version.split("."))) >= int("".join(analyzer_version.split("."))):
                _LOGGER.info(f"Skipping SI-cloc report: {document_id} because has version: {version}")
                return pd.DataFrame()

        # Create metadata dataframe
        metadata_df = self.create_si_cloc_metadata_dataframe(si_cloc_report, analyzer_version=analyzer_version)

        if analyzer_version and metadata_df.empty:
            _LOGGER.info(f"Skipping SI-cloc report: {document_id} because has version: {version}")
            return pd.DataFrame()

        package_name = metadata_df["package_name"][0]
        package_version = metadata_df["package_version"][0]
        package_index = metadata_df["package_index"][0]

        _LOGGER.info(f"Analyzing si_cloc report for package_name: {package_name}")
        _LOGGER.info(f"Analyzing si_cloc report for package_version: {package_version}")
        _LOGGER.info(f"Analyzing si_cloc report for package_index: {package_index}")

        # Create cloc results dataframe
        cloc_results_df = self.create_si_cloc_results_dataframe(si_cloc_report=si_cloc_report)

        report_summary_df = self.produce_si_cloc_report_summary_dataframe(
            metadata_df=metadata_df,
            cloc_results_df=cloc_results_df,
        )

        return report_summary_df

    def aggregate_si_cloc_final_dataframes(
        self,
        si_cloc_reports: List[Dict[str, Any]],
        analyzer_version: Optional[str] = None,
    ) -> pd.DataFrame:
        """Aggregate si-cloc dataframes into final dataframe.

        :param si_cloc_reports: list of SI cloc report provided by Thoth SI cloc analyzer.
        :param analyzer_version: analyzer version filter

        :output final_df: pandas.DataFrame aggregating all SI cloc reports provided.
        """
        counter = 1
        total_reports = len(si_cloc_reports)

        final_df = pd.DataFrame()

        for si_cloc_report in si_cloc_reports:

            document_id = si_cloc_report["metadata"]["document_id"]
            _LOGGER.info(f"Analyzing SI-cloc report: {counter}/{total_reports}")

            si_cloc_report_summary_df = self.create_si_cloc_final_dataframe(
                si_cloc_report=si_cloc_report,
                analyzer_version=analyzer_version,
            )

            if not si_cloc_report_summary_df.empty:
                final_df = pd.concat([final_df, si_cloc_report_summary_df], axis=0)

                counter += 1
            else:
                _LOGGER.info(f"Skipping SI-cloc report: {document_id} because has different version")

        final_df.reset_index(inplace=True, drop=True)

        return final_df


class SecurityIndicatorsAggregator:
    """Class of methods used to aggregate reports from Security Indicators (SI) analyzers."""

    si_bandit = SecurityIndicatorsBandit()
    si_cloc = SecurityIndicatorsCloc()

    @staticmethod
    def retrieve_security_indicator_aggregated_results(
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = False,
        security_indicator_aggregated_repo_path: Path = Path("security-indicators"),
    ) -> List[Any]:
        """Retrieve si_aggregated results from Ceph or locally using the provided path.

        :param limit_results: reduce the number of si_aggregated reports ids considered to `max_ids` to test analysis.
        :param max_ids: maximum number of si_aggregated reports ids considered.
        :param is_local: flag to retreive the dataset locally or from S3 (credentials are required).
        :param si_aggregated_repo_path: path to retrieve the si_aggregated data locally and `is_local` is set to True.
        """
        document_name = "aggregated"

        si_reports: Dict[str, Any] = _SecurityIndicators().aggregate_thoth_security_indicators_results(
            store_files=[document_name],
            limit_results=limit_results,
            max_ids=max_ids,
            is_local=is_local,
            repo_path=security_indicator_aggregated_repo_path,
        )
        security_indicator_aggregated_reports = [
            document_results[document_name]
            for document_id, document_results in si_reports.items()
            if document_name in document_results
        ]

        _LOGGER.info("Number of files that can be used is: %r" % len(security_indicator_aggregated_reports))

        return security_indicator_aggregated_reports

    def create_si_aggregated_results(
        self,
        si_bandit_report: Dict[str, Any],
        si_cloc_report: Dict[str, Any],
        filters_files: Optional[List[str]] = None,
        si_bandit_version: Optional[str] = None,
        si_cloc_version: Optional[str] = None,
        output_json: bool = False,
    ) -> Union[pd.DataFrame, Dict[str, Any]]:
        """Create dataframe or json with aggregated data from SI analyzers.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param si_cloc_report: SI cloc report provided by Thoth SI cloc analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.
        :param si_bandit_version: filter for si bandit analyzer version
        :param si_cloc_version: filter for si cloc analyzer version
        :param output_json: if json output is required

        :output aggregated_df: pandas.DataFrame aggregating all SI analyzers reports provided.
        :output aggregated_json: pandas.DataFrame aggregating all SI analyzers reports provided.
        """
        aggregated_df = pd.DataFrame()
        si_bandit_df = self.si_bandit.create_si_bandit_final_dataframe(
            si_bandit_report=si_bandit_report,
            filters_files=filters_files,
            analyzer_version=si_bandit_version,
        )
        si_cloc_df = self.si_cloc.create_si_cloc_final_dataframe(
            si_cloc_report=si_cloc_report,
            analyzer_version=si_cloc_version,
        )
        if si_bandit_df.empty or si_cloc_df.empty:
            _LOGGER.exception("One of the analyzer results is empty!")

        package_info = ["package_name", "package_version", "package_index"]
        si_bandit_package = set(str(v) for v in si_bandit_df[package_info].values)
        si_cloc_package = set(str(v) for v in si_cloc_df[package_info].values)

        if si_bandit_package - si_cloc_package:
            raise ThothSIPackageNotMatchingException(
                "The reports are from different packages, cannot be aggregated!"
                f"\nsi_bandit:{si_bandit_package}"
                f"\nsi_cloc: {si_cloc_package}",
            )

        package_df = si_bandit_df[package_info]

        si_bandit_df.drop(columns=package_info, inplace=True)
        si_cloc_df.drop(columns=package_info, inplace=True)

        aggregated_df = pd.concat([package_df, si_bandit_df, si_cloc_df], axis=1)

        aggregated_df.reset_index(inplace=True, drop=True)

        if output_json:
            aggregated_si = aggregated_df.to_json(orient="records")  # string

            aggregated_json: Dict[str, Any] = json.loads(aggregated_si)[0]

            return aggregated_json

        return aggregated_df
