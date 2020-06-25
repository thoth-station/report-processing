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

"""Security Indicators report processing."""


import logging
import json

from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

import pandas as pd

from thoth.report_processing.utils import aggregate_thoth_results
from thoth.report_processing.exceptions import ThothSIPackageNotMatchingException

_LOGGER = logging.getLogger("thoth.lab.security")

logging.basicConfig(level=logging.INFO)


class SecurityIndicatorsBandit:
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
        is_local: bool = True,
        security_indicator_bandit_repo_path: Path = Path("security/si-bandit"),
    ) -> List[Any]:
        """Aggregate si_bandit results from Ceph or locally using the provided path.

        :param limit_results: reduce the number of si_bandit reports ids considered to `max_ids` to test analysis.
        :param max_ids: maximum number of si_bandit reports ids considered.
        :param is_local: flag to retreive the dataset locally or from S3 (credentials are required).
        :param si_bandit_repo_path: path to retrieve the si_bandit dataset locally and `is_local` is set to True.
        """
        security_indicator_bandit_reports: List[Any] = aggregate_thoth_results(
            limit_results=limit_results,
            max_ids=max_ids,
            is_local=is_local,
            repo_path=security_indicator_bandit_repo_path,
            store_name="si_bandit",
        )

        return security_indicator_bandit_reports

    @staticmethod
    def extract_data_from_si_bandit_metadata(si_bandit_report: Dict[str, Any]) -> Dict[str, Any]:
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

    def create_si_bandit_metadata_dataframe(self, si_bandit_report: Dict[str, Any]) -> pd.DataFrame:
        """Create si-bandit report metadata dataframe.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.

        :output metadata_df: pandas.DataFrame with metadata obtained from `extract_data_from_si_bandit_metadata`.
        """
        metadata_si_bandit = self.extract_data_from_si_bandit_metadata(si_bandit_report=si_bandit_report)
        metadata_df = pd.DataFrame([metadata_si_bandit])

        return metadata_df

    @staticmethod
    def extract_severity_confidence_info(
        si_bandit_report: Dict[str, Any], filters_files: Optional[List[str]] = None
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
        self, si_bandit_report: Dict[str, Any], filters_files: Optional[List[str]] = None
    ) -> Tuple[pd.DataFrame, Dict[str, int]]:
        """Create Security/Confidence dataframe for si-bandit report.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.

        :output sec_conf_df: pandas.DataFrame with all info about SEVERITY/CONFIDENCE for the package analyzed.
        :output summary_files: dictionary with statistics about analyzed, filtered total files.
        """
        results_sec_conf, summary_files = self.extract_severity_confidence_info(
            si_bandit_report=si_bandit_report, filters_files=filters_files
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
        metadata_df: pd.DataFrame, si_bandit_sec_conf_df: pd.DataFrame, summary_files: Dict[str, int]
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
            summary_files["number_of_files_with_severities"]
        )
        report_summary_df["number_of_analyzed_files"] = pd.to_numeric(summary_files["number_of_analyzed_files"])
        report_summary_df["number_of_filtered_files"] = pd.to_numeric(summary_files["number_of_filtered_files"])
        report_summary_df["number_of_files_total"] = pd.to_numeric(
            summary_files["number_of_filtered_files"]
        ) + pd.to_numeric(summary_files["number_of_analyzed_files"])
        report_summary_df["_total_severity"] = pd.to_numeric(report_summary_df["_total_severity"])

        return report_summary_df

    def create_si_bandit_final_dataframe(
        self, si_bandit_report: Dict[str, Any], filters_files: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """Create final si-bandit dataframe.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.

        :output report_summary_df: pandas.DataFrame summary for a single si bandit report.
        """
        # Create metadata dataframe
        metadata_df = self.create_si_bandit_metadata_dataframe(si_bandit_report=si_bandit_report)

        package_name = metadata_df["package_name"][0]
        package_version = metadata_df["package_version"][0]
        package_index = metadata_df["package_index"][0]

        _LOGGER.info(f"Analyzing si_bandit report for package_name: {package_name}")
        _LOGGER.info(f"Analyzing si_bandit report for package_version: {package_version}")
        _LOGGER.info(f"Analyzing si_bandit report for package_index: {package_index}")

        # Create Security/Confidence dataframe
        security_confidence_df, summary_files = self.create_security_confidence_dataframe(
            si_bandit_report=si_bandit_report, filters_files=filters_files
        )

        # Create Summary dataframe
        si_bandit_report_summary_df = self.produce_si_bandit_report_summary_dataframe(
            metadata_df=metadata_df, si_bandit_sec_conf_df=security_confidence_df, summary_files=summary_files
        )

        return si_bandit_report_summary_df

    def aggregate_si_bandit_final_dataframe(
        self, si_bandit_reports: List[Dict[str, Any]], filters_files: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """Aggregate si-bandit dataframes into final dataframe.

        :param si_bandit_reports: list of SI bandit report provided by Thoth SI bandit analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.

        :output final_df: pandas.DataFrame aggregating all SI bandit reports provided.
        """
        counter = 1
        final_df = pd.DataFrame()
        total_reports = len(si_bandit_reports)

        for si_bandit_report in si_bandit_reports:

            _LOGGER.info(f"Analyzing SI-bandit report: {counter}/{total_reports}")

            si_bandit_report_summary_df = self.create_si_bandit_final_dataframe(
                si_bandit_report=si_bandit_report, filters_files=filters_files
            )

            final_df = pd.concat([final_df, si_bandit_report_summary_df], axis=0)

            counter += 1

        return final_df

    def create_security_indicators_scores(self, si_bandit_df: pd.DataFrame) -> pd.DataFrame:
        """Create Security Indicators (SI) scores from si bandit outputs.

        :param si_bandit_df: pandas.Dataframe as given by `aggregate_si_bandit_final_dataframe`.

        :output si_bandit_df: Extend `si_bandit_df` with SI scores created using all rows (aka all packages).
        """
        for security in ["LOW", "MEDIUM", "HIGH"]:
            for confidence in ["LOW", "MEDIUM", "HIGH"]:

                vulnerability_class = f"SEVERITY.{security}__CONFIDENCE.{confidence}"

                min_max_scaler = (si_bandit_df[vulnerability_class] - si_bandit_df[vulnerability_class].min()) / (
                    si_bandit_df[vulnerability_class].max() - si_bandit_df[vulnerability_class].min()
                )

                si_bandit_df[f"{vulnerability_class}_scaled"] = min_max_scaler

        si_bandit_df["SEVERITY.HIGH.sub_score"] = (
            si_bandit_df["SEVERITY.HIGH__CONFIDENCE.HIGH"].fillna(0) * self.HIGH_CONFIDENCE_WEIGHT
            + si_bandit_df["SEVERITY.HIGH__CONFIDENCE.MEDIUM"].fillna(0) * self.MEDIUM_CONFIDENCE_WEIGHT
            + si_bandit_df["SEVERITY.HIGH__CONFIDENCE.LOW"].fillna(0) * self.LOW_CONFIDENCE_WEIGHT
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
        is_local: bool = True,
        security_indicator_cloc_repo_path: Path = Path("security/si-cloc"),
    ) -> List[Any]:
        """Aggregate si_cloc results from Ceph or locally using the provided path.

        :param limit_results: reduce the number of si_cloc reports ids considered to `max_ids` to test analysis
        :param max_ids: maximum number of si_cloc reports ids considered
        :param is_local: flag to retreive the dataset locally or from S3 (credentials are required)
        :param si_cloc_repo_path: path to retrieve the si_cloc dataset locally and `is_local` is set to True
        """
        security_indicator_cloc_reports: List[Any] = aggregate_thoth_results(
            limit_results=limit_results,
            max_ids=max_ids,
            is_local=is_local,
            repo_path=security_indicator_cloc_repo_path,
            store_name="si_cloc",
        )

        return security_indicator_cloc_reports

    @staticmethod
    def extract_data_from_si_cloc_metadata(si_cloc_report: Dict[str, Any]) -> Dict[str, Any]:
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
            "package_name": report_metadata["arguments"]["app.py"]["package_name"],
            "package_version": report_metadata["arguments"]["app.py"]["package_version"],
            "package_index": report_metadata["arguments"]["app.py"]["package_index"],
        }

        return extracted_metadata

    def create_si_cloc_metadata_dataframe(self, si_cloc_report: Dict[str, Any]) -> pd.DataFrame:
        """Create si-cloc report metadata dataframe.

        :param si_cloc_report: SI cloc report provided by Thoth SI cloc analyzer.

        :output metadata_df: pandas.DataFrame with metadata obtained from `extract_data_from_si_cloc_metadata`.
        """
        metadata_si_cloc = self.extract_data_from_si_cloc_metadata(si_cloc_report=si_cloc_report)
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
        metadata_df: pd.DataFrame, cloc_results_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Create si-cloc report summary dataframe.

        :param metadata_df: pandas.DataFrame provided by `create_si_cloc_metadata_dataframe`.
        :param cloc_results_df: pandas.DataFrame provided by `create_si_cloc_results_dataframe`.

        :output report_summary_df: pandas.DataFrame summary for a single si cloc report.
        """
        report_summary_df = pd.concat([metadata_df, cloc_results_df], axis=1)

        return report_summary_df

    def create_si_cloc_final_dataframe(self, si_cloc_report: Dict[str, Any]) -> pd.DataFrame:
        """Create final si-cloc final dataframe.

        :param si_cloc_report: SI cloc report provided by Thoth SI cloc analyzer.

        :output report_summary_df: pandas.DataFrame summary for a single si cloc report.
        """
        # Create metadata dataframe
        metadata_df = self.create_si_cloc_metadata_dataframe(si_cloc_report)

        package_name = metadata_df["package_name"][0]
        package_version = metadata_df["package_version"][0]
        package_index = metadata_df["package_index"][0]

        _LOGGER.info(f"Analyzing si_cloc report for package_name: {package_name}")
        _LOGGER.info(f"Analyzing si_cloc report for package_version: {package_version}")
        _LOGGER.info(f"Analyzing si_cloc report for package_index: {package_index}")

        # Create cloc results dataframe
        cloc_results_df = self.create_si_cloc_results_dataframe(si_cloc_report=si_cloc_report)

        report_summary_df = self.produce_si_cloc_report_summary_dataframe(
            metadata_df=metadata_df, cloc_results_df=cloc_results_df
        )

        return report_summary_df

    def aggregate_si_cloc_final_dataframes(self, si_cloc_reports: List[Dict[str, Any]]) -> pd.DataFrame:
        """Aggregate si-cloc dataframes into final dataframe.

        :param si_cloc_reports: list of SI cloc report provided by Thoth SI cloc analyzer.

        :output final_df: pandas.DataFrame aggregating all SI cloc reports provided.
        """
        counter = 1
        total_reports = len(si_cloc_reports)

        final_df = pd.DataFrame()

        for si_cloc_report in si_cloc_reports:

            _LOGGER.info(f"Analyzing SI-cloc report: {counter}/{total_reports}")
            si_cloc_report_summary_df = self.create_si_cloc_final_dataframe(si_cloc_report=si_cloc_report)

            final_df = pd.concat([final_df, si_cloc_report_summary_df], axis=0)

            counter += 1

        return final_df


class SecurityIndicatorsAggregator:
    """Class of methods used to aggregate reports from Security Indicators (SI) analyzers."""

    si_bandit = SecurityIndicatorsBandit()
    si_cloc = SecurityIndicatorsCloc()

    def create_si_aggregated_dataframe(
        self,
        si_bandit_report: Dict[str, Any],
        si_cloc_report: Dict[str, Any],
        filters_files: Optional[List[str]] = None,
    ) -> pd.DataFrame:
        """Create dataframe with aggregated data from SI analyzers.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param si_cloc_report: SI cloc report provided by Thoth SI cloc analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.

        :output aggregated_df: pandas.DataFrame aggregating all SI analyzers reports provided.
        """
        aggregated_df = pd.DataFrame()
        si_bandit_df = self.si_bandit.create_si_bandit_final_dataframe(
            si_bandit_report=si_bandit_report, filters_files=filters_files
        )
        si_cloc_df = self.si_cloc.create_si_cloc_final_dataframe(si_cloc_report=si_cloc_report)

        package_info = ["package_name", "package_version", "package_index"]
        si_bandit_package = set(str(v) for v in si_bandit_df[package_info].values)
        si_cloc_package = set(str(v) for v in si_cloc_df[package_info].values)

        if si_bandit_package - si_cloc_package:
            raise ThothSIPackageNotMatchingException(
                "The reports are from different packages, cannot be aggregated!"
                f"\nsi_bandit:{si_bandit_package}"
                f"\nsi_cloc: {si_cloc_package}"
            )

        package_df = si_bandit_df[package_info]

        si_bandit_df.drop(columns=package_info, inplace=True)
        si_cloc_df.drop(columns=package_info, inplace=True)

        aggregated_df = pd.concat([package_df, si_bandit_df, si_cloc_df], axis=1)

        return aggregated_df

    def create_si_aggregated_json(
        self,
        si_bandit_report: Dict[str, Any],
        si_cloc_report: Dict[str, Any],
        filters_files: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create json with aggregated data from SI analyzers.

        :param si_bandit_report: SI bandit report provided by Thoth SI bandit analyzer.
        :param si_cloc_report: SI cloc report provided by Thoth SI cloc analyzer.
        :param filters_files: List of strings of files to be filtered from analysis
        e.g. filter_files = ['/tests'] where /tests is filtered in the file path.

        :output: json file with aggregated SI analyzers reports provided.
        """
        aggregated_df = self.create_si_aggregated_dataframe(
            si_bandit_report=si_bandit_report, si_cloc_report=si_cloc_report, filters_files=filters_files
        )
        aggregated_si = aggregated_df.to_json(orient="records")  # string

        aggregated_json: Dict[str, Any] = json.loads(aggregated_si)[0]

        return aggregated_json
