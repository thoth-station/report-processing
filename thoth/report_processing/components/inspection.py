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

"""Amun Inspection reports processing methods."""

import os
import logging
import json
import copy
import hashlib

from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Iterable

from sklearn.preprocessing import LabelEncoder

from numpy import array
import numpy as np
import pandas as pd

from thoth.report_processing.exceptions import ThothNotKnownResultStore
from thoth.report_processing.exceptions import ThothMissingDatasetAtPath
from thoth.report_processing.enums import ThothAmunInspectionFileStoreEnum

from thoth.storages.inspections import InspectionStore

# set up logging
DEBUG_LEVEL = bool(int(os.getenv("DEBUG_LEVEL", 0)))

if DEBUG_LEVEL:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

_LOGGER = logging.getLogger(__name__)


class AmunInspections:
    """Class of methods used to process reports from Amun Inspections."""

    _INSPECTION_PERFORMANCE_VALUES = {"elapsed_time": "stdout__@result__elapsed", "rate": "stdout__@result__rate"}

    _INSPECTION_USAGE_VALUES = [
        "usage__ru_inblock",
        "usage__ru_majflt",
        "usage__ru_maxrss",
        "usage__ru_minflt",
        "usage__ru_nivcsw",
        "usage__ru_nvcsw",
        "usage__ru_stime",
        "usage__ru_utime",
    ]

    @classmethod
    def aggregate_thoth_inspections_results(
        cls,
        store_files: Optional[List[str]] = None,
        inspections_identifiers: Optional[List[str]] = None,
        inspection_ids_list: Optional[List[str]] = None,
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = False,
        repo_path: Optional[Path] = None,
        store_locally: bool = False,
        store_locally_repo_name: str = "./inspections",
    ) -> Dict[str, Any]:
        """Aggregate results stored on Ceph or locally from repo for Thoth components reports.

        :param store_files: files to be retrieved from the Store for each result, if None all files are retrieved.
        :param inspections_identifiers: Inspection identifiers in inspection IDs.
        :param inspection_ids_list: Inspection IDs list.
        :param limit_results: reduce the number of reports ids considered to `max_ids`.
        :param max_ids: maximum number of reports ids considered.
        :param is_local: flag to retrieve the dataset locally (if not uses Ceph S3 (credentials are required)).
        :param repo_path: required if you want to retrieve the dataset locally and `is_local` is set to True.
        :param store_locally: required if you want to store the dataset retrieved from Ceph.
        :param store_locally_repo_name: repo name where to store the dataset retrieved from Ceph,
                './inspections' by default.
        """
        if store_files:
            if any(store_file not in ThothAmunInspectionFileStoreEnum.__members__ for store_file in store_files):
                raise ThothNotKnownResultStore(
                    f"InspectionStore does not contain some of the files listed: {store_files}."
                    f"InspectionStore: {ThothAmunInspectionFileStoreEnum.__members__.keys()}",
                )

        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids}!")

        files: Dict[str, Any] = {}

        if not store_files:
            store_files = ["results", "specification", "hardware_info", "build_logs"]

        if is_local:
            files, counter = cls._aggregate_inspections_from_local(
                repo_path=repo_path,
                inspections_identifiers=inspections_identifiers,
                files=files,
                limit_results=limit_results,
                max_ids=max_ids,
                store_files=store_files,
            )

        else:
            files, counter = cls._aggregate_inspections_from_ceph(
                store_files=store_files,
                inspections_identifiers=inspections_identifiers,
                inspection_ids_list=inspection_ids_list,
                files=files,
                limit_results=limit_results,
                max_ids=max_ids,
                store_locally=store_locally,
                store_locally_repo_name=store_locally_repo_name,
            )

        _LOGGER.info("Number of files retrieved is: %r" % counter)

        return files

    @classmethod
    def _aggregate_inspections_from_local(
        cls,
        files: Dict[str, Any],
        store_files: Optional[List[str]] = None,
        inspections_identifiers: Optional[List[str]] = None,
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

        # Iterate through inspection IDs
        for result_path in repo_path.iterdir():
            inspection_document_id = result_path.name

            identifier_check = False

            if inspections_identifiers:

                identifier_check = cls._has_inspection_identifier(
                    inspection_document_id,
                    inspections_identifiers,
                )

            if inspections_identifiers and not identifier_check:
                _LOGGER.info(f"Skipping inspection ID... {inspection_document_id}")
                # If identifiers are requested and inspection id does not contain any of them, skip it
                continue

            _LOGGER.info(f"Considering inspection ID... {inspection_document_id}")

            retrieved_files: List[Dict[str, Any]] = []
            try:
                # Iterate through inspection results number
                for inspection_number_path in Path(f"{result_path}/results").iterdir():
                    _LOGGER.info(
                        f"Considering inspection ID {inspection_document_id}." f"Number {inspection_number_path.name}",
                    )

                    file_info: Dict[str, Any] = {}

                    if store_files and ThothAmunInspectionFileStoreEnum.results.name in store_files:

                        with open(f"{inspection_number_path}/result", "r") as result_file:
                            inspection_result_document = json.load(result_file)

                            file_info["result"] = inspection_result_document
                            file_info["result"]["inspection_document_id"] = inspection_document_id

                        if store_files and ThothAmunInspectionFileStoreEnum.hardware_info.name in store_files:

                            with open(f"{inspection_number_path}/hwinfo", "r") as hwinfo_file:
                                inspection_hw_info = json.load(hwinfo_file)

                                file_info["hwinfo"] = inspection_hw_info

                        if store_files and ThothAmunInspectionFileStoreEnum.job_logs.name in store_files:

                            with open(f"{inspection_number_path}/log", "r") as job_log_file:
                                inspection_job_logs = job_log_file.read()

                                file_info["job_logs"] = inspection_job_logs

                    if file_info:
                        retrieved_files.append(file_info)

            except Exception as retrieval_error:
                _LOGGER.info(
                    f"Considering inspection ID {inspection_document_id}."
                    f"No files retrieved due to the following error: {retrieval_error}",
                )

            if retrieved_files:
                files[inspection_document_id] = {"results": retrieved_files}
            else:
                files[inspection_document_id] = {}

            try:
                if store_files and ThothAmunInspectionFileStoreEnum.specification.name in store_files:

                    with open(f"{result_path}/build/specification", "r") as specification_file:
                        inspection_specification_document = json.load(specification_file)

                        if retrieved_files:
                            modified_results = []
                            for result in files[inspection_document_id]["results"]:
                                result["result"]["identifier"] = inspection_specification_document["identifier"]
                                result["result"]["specification_base"] = inspection_specification_document["base"]
                                result["result"]["batch_size"] = inspection_specification_document["batch_size"]
                                result["requirements"] = inspection_specification_document["python"]["requirements"]

                                requirements_locked = cls._parse_requirements_locked(
                                    requirements_locked=inspection_specification_document["python"][
                                        "requirements_locked"
                                    ],
                                )
                                result["result"]["requirements_locked"] = requirements_locked

                                result["result"]["run"] = inspection_specification_document["run"]

                                modified_results.append(result)

                            files[inspection_document_id] = {"results": modified_results}

                        files[inspection_document_id]["specification"] = inspection_specification_document

            except Exception as retrieval_error:
                _LOGGER.info(
                    f"Considering inspection ID {inspection_document_id}."
                    f"No build specification retrieved due to the following error: {retrieval_error}",
                )

            try:
                if store_files and ThothAmunInspectionFileStoreEnum.build_logs.name in store_files:

                    with open(f"{result_path}/build/log", "r") as build_logs_type:
                        inspection_build_logs = build_logs_type.read()

                        files[inspection_document_id]["build_logs"] = inspection_build_logs

            except Exception as retrieval_error:
                _LOGGER.info(
                    f"Considering inspection ID {inspection_document_id}."
                    f"No build log retrieved due to the following error: {retrieval_error}",
                )

            if files[inspection_document_id]:
                counter += 1

                if limit_results:
                    if counter == max_ids:
                        return files, counter
            else:
                files.pop(inspection_document_id)

        return files, counter

    @staticmethod
    def _has_inspection_identifier(
        inspection_id: str,
        inspections_identifiers: List[str],
    ) -> bool:
        """Check if inspection id has identifier."""
        inspection_id_pieces = inspection_id.split("-")

        for identifier in inspections_identifiers:
            identifier_pieces = identifier.split("-")
            if not set(identifier_pieces) - set(inspection_id_pieces):
                # The inspection id has the correct identifier requested
                return True

        # The inspection id does not has the identifier requested
        return False

    @staticmethod
    def _retrieve_inspection_results_from_ceph(
        inspection_document_id: str,
        inspection_store: InspectionStore,
        store_locally_repo_name: str,
        store_files: Optional[List[str]] = None,
        store_locally: bool = False,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Retrieve inspection results for inspection ID."""
        _LOGGER.info(f"Document id: {inspection_document_id}")
        number_results = inspection_store.results.get_results_count()

        if number_results == 0:
            _LOGGER.warning(f"No inspection results identified for inspection ID: {inspection_document_id}")
            return [], 0

        # Inspection ID result counter
        inspection_result_counter = 0

        retrieved_files: List[Dict[str, Any]] = []

        for inspection_result_number in range(number_results):

            file_info: Dict[str, Any] = {}

            try:

                if store_files and ThothAmunInspectionFileStoreEnum.results.name in store_files:
                    inspection_result_document = inspection_store.results.retrieve_result(
                        item=inspection_result_number,
                    )

                    file_info["result"] = inspection_result_document
                    file_info["result"]["inspection_document_id"] = inspection_document_id

                    if store_locally:
                        result_path = (
                            f"{store_locally_repo_name}/{inspection_document_id}/results/{inspection_result_number}"
                        )
                        if not os.path.exists(result_path):
                            os.makedirs(result_path)

                    with open(
                        f"{store_locally_repo_name}/{inspection_document_id}/results/{inspection_result_number}/result",
                        "w",
                    ) as result_file:
                        result_file.write(json.dumps(inspection_result_document))

                if store_files and ThothAmunInspectionFileStoreEnum.hardware_info.name in store_files:
                    inspection_hw_info = inspection_store.results.retrieve_hwinfo(
                        item=inspection_result_number,
                    )

                    file_info["hwinfo"] = inspection_hw_info

                    if store_locally:
                        with open(
                            f"{store_locally_repo_name}/{inspection_document_id}/results/{inspection_result_number}/hwinfo",
                            "w",
                        ) as hw_file:
                            hw_file.write(json.dumps(inspection_hw_info))

                if store_files and ThothAmunInspectionFileStoreEnum.job_logs.name in store_files:
                    inspection_job_logs = inspection_store.results.retrieve_log(item=inspection_result_number)

                    file_info["job_logs"] = inspection_job_logs

                    if store_locally:
                        with open(
                            f"{store_locally_repo_name}/{inspection_document_id}/results/{inspection_result_number}/log",
                            "w",
                        ) as log_file:
                            log_file.write(inspection_job_logs)

                inspection_result_counter += 1

                _LOGGER.info(
                    "From inspection id %r results number identifier retrieved: %r",
                    inspection_document_id,
                    inspection_result_number,
                )

                if file_info:
                    retrieved_files.append(file_info)

            except Exception as inspection_exception:
                _LOGGER.exception(
                    f"Exception during retrieval of inspection id {inspection_document_id} results"
                    f"n.{inspection_result_number}: {inspection_exception}",
                )
                pass

        return retrieved_files, inspection_result_number

    @staticmethod
    def _retrieve_build_specification_from_ceph(
        inspection_document_id: str,
        inspection_store: InspectionStore,
        store_locally_repo_name: str,
        store_files: Optional[List[str]] = None,
        store_locally: bool = False,
    ) -> Any:
        """Retrieve inspection build specification for inspection ID."""
        if store_files and ThothAmunInspectionFileStoreEnum.specification.name in store_files:

            try:
                inspection_specification_document = inspection_store.retrieve_specification()

            except Exception as inspection_exception:
                _LOGGER.exception(
                    f"Exception during retrieval of inspection build specification for"
                    f"inspection id {inspection_document_id}: {inspection_exception}",
                )
                return None

            if store_locally:
                with open(
                    f"{store_locally_repo_name}/{inspection_document_id}/build/specification",
                    "w",
                ) as specification_file:
                    specification_file.write(json.dumps(inspection_specification_document))

            return inspection_specification_document

        else:
            return None

    @staticmethod
    def _retrieve_build_logs_from_ceph(
        inspection_document_id: str,
        inspection_store: InspectionStore,
        store_locally_repo_name: str,
        store_files: Optional[List[str]] = None,
        store_locally: bool = False,
    ) -> Any:
        """Retrieve inspection build logs for inspection ID."""
        if store_files and ThothAmunInspectionFileStoreEnum.build_logs.name in store_files:

            try:
                inspection_build_logs = inspection_store.build.retrieve_log()

            except Exception as inspection_exception:
                _LOGGER.exception(
                    f"Exception during retrieval of inspection build logs for"
                    f"inspection id {inspection_document_id}: {inspection_exception}",
                )
                return None

            if store_locally:
                with open(f"{store_locally_repo_name}/{inspection_document_id}/build/log", "w") as build_log_file:
                    build_log_file.write(inspection_build_logs)

            return inspection_build_logs

        else:
            return None

    @classmethod
    def _aggregate_inspections_from_ceph(
        cls,
        files: Dict[str, Any],
        store_locally_repo_name: str,
        store_files: Optional[List[str]] = None,
        inspections_identifiers: Optional[List[str]] = None,
        inspection_ids_list: Optional[List[str]] = None,
        limit_results: bool = False,
        max_ids: int = 5,
        store_locally: bool = False,
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from Ceph."""
        store_class_type = InspectionStore

        # Inspection ID counter
        files_retrieved_counter = 0

        if store_locally:
            if not os.path.exists(store_locally_repo_name):
                os.mkdir(store_locally_repo_name)

        for inspection_document_id in inspection_ids_list or store_class_type.iter_inspections():

            identifier_check = False

            if inspections_identifiers:

                identifier_check = cls._has_inspection_identifier(
                    inspection_document_id,
                    inspections_identifiers,
                )

            if inspections_identifiers and not identifier_check:
                # If identifiers are requested and inspection id does not contain any of them, skip it
                continue

            inspection_store = InspectionStore(inspection_id=inspection_document_id)
            inspection_store.connect()

            retrieved_files, _ = cls._retrieve_inspection_results_from_ceph(
                inspection_document_id=inspection_document_id,
                inspection_store=inspection_store,
                store_files=store_files,
                store_locally=store_locally,
                store_locally_repo_name=store_locally_repo_name,
            )

            if store_locally:
                build_path = f"{store_locally_repo_name}/{inspection_document_id}/build/"
                if not os.path.exists(build_path):
                    os.makedirs(build_path)

            build_specification_file = cls._retrieve_build_specification_from_ceph(
                inspection_document_id=inspection_document_id,
                inspection_store=inspection_store,
                store_files=store_files,
                store_locally=store_locally,
                store_locally_repo_name=store_locally_repo_name,
            )

            if retrieved_files and build_specification_file:
                modified_results = []

                for result in retrieved_files:
                    result["result"]["identifier"] = build_specification_file["identifier"]
                    result["result"]["specification_base"] = build_specification_file["base"]
                    result["result"]["batch_size"] = build_specification_file["batch_size"]
                    result["requirements"] = build_specification_file["python"]["requirements"]

                    requirements_locked = cls._parse_requirements_locked(
                        requirements_locked=build_specification_file["python"]["requirements_locked"],
                    )
                    result["result"]["requirements_locked"] = requirements_locked

                    result["result"]["run"] = build_specification_file["run"]

                    modified_results.append(result)

                files[inspection_document_id] = {"results": modified_results}
            else:
                files[inspection_document_id] = {}

            if build_specification_file:
                files[inspection_document_id]["specification"] = build_specification_file

            build_info_file = cls._retrieve_build_logs_from_ceph(
                inspection_document_id=inspection_document_id,
                inspection_store=inspection_store,
                store_files=store_files,
                store_locally=store_locally,
                store_locally_repo_name=store_locally_repo_name,
            )

            if build_info_file:
                files[inspection_document_id]["build_logs"] = build_info_file

            if files[inspection_document_id]:
                _LOGGER.info(f"Retrieved file n. {files_retrieved_counter}")
                files_retrieved_counter += 1

                if limit_results:
                    if files_retrieved_counter == max_ids:
                        return files, files_retrieved_counter
            else:
                files.pop(inspection_document_id)

        return files, files_retrieved_counter

    @staticmethod
    def _parse_requirements_locked(requirements_locked: Dict[str, Any]) -> Dict[str, Any]:
        """Parse requirements_locked to make sure name, version, index is present."""
        default = requirements_locked["default"]
        for package_name, data in default.items():

            # Use PyPI index as default if index is missing
            if "index" not in data.keys():
                modified_data = data.copy()
                modified_data["index"] = "pypi"
                requirements_locked["default"][package_name].update(modified_data)

        return requirements_locked

    @classmethod
    def process_inspection_runs(
        cls,
        inspection_runs: Dict[str, Any],
        filter_by_batch_size: int = 1,
    ) -> Tuple[Dict[str, pd.DataFrame], Dict[str, pd.DataFrame]]:
        """Process inspection runs into pd.DataFrame for each inspection ID.

        :param inspection_runs: aggregated data provided by `aggregate_thoth_inspections_runs`.
        :param filter_by_batch_size: filter inspection to guarantee all have same batch size.
        """
        processed_inspection_runs: Dict[str, pd.DataFrame] = {}
        failed_inspection_runs: Dict[str, pd.DataFrame] = {}

        if not inspection_runs:
            _LOGGER.exception("Empty iterable provided.")
            return processed_inspection_runs, failed_inspection_runs

        for inspection_id, inspection_run in inspection_runs.items():

            if "results" not in inspection_run.keys():
                _LOGGER.warning(
                    f"Inspection ID {inspection_id} has not results, discarding...",
                )
                continue

            inspection_run_df = cls.process_inspection_run(inspection_run=inspection_run)

            if any(exit_code != 0 for exit_code in inspection_run_df["exit_code"].values):
                _LOGGER.warning(
                    f"Inspection ID {inspection_id} has batch size of: {inspection_run_df.shape[0]}"
                    f" but some of them are failed.",
                )
                failed_inspection_runs[inspection_id] = inspection_run_df

            elif inspection_run_df.shape[0] >= filter_by_batch_size:
                processed_inspection_runs[inspection_id] = inspection_run_df

            else:
                _LOGGER.warning(
                    f"Inspection ID {inspection_id} has batch size of: {inspection_run_df.shape[0]}"
                    f"... discarding due to filter set to: {filter_by_batch_size}",
                )

        return processed_inspection_runs, failed_inspection_runs

    @staticmethod
    def process_inspection_run(inspection_run: Dict[str, Any]) -> pd.DataFrame:
        """Process an inspection run into pd.DataFrame.

        :param inspection_run: single aggregated inspection ID provided by `aggregate_thoth_inspections_runs`.
        """
        results = inspection_run["results"]
        final_df = pd.DataFrame()

        inspection_numbers = []
        inspection_number = 0

        for inspection in results:
            inspection_result_df = pd.json_normalize(inspection["result"], sep="__")

            final_df = pd.concat([final_df, inspection_result_df], axis=0)
            inspection_numbers.append(inspection_number)
            inspection_number += 1

        final_df.reset_index(inplace=True, drop=True)
        final_df["inspection_number"] = inspection_numbers

        return final_df

    @staticmethod
    def evaluate_statistics_on_inspection_df(
        inspection_df: pd.DataFrame,
        column_names: List[str],
        extra_columns: List[str],
    ) -> pd.DataFrame:
        """Evaluate statistics on performance values selected from Dataframe columns."""
        unashable_columns = inspection_df.applymap(lambda x: isinstance(x, dict) or isinstance(x, list)).all()[
            lambda x: x == True  # noqa
        ]
        new_data = {}

        inspection_start = None
        inspection_end = None
        inspection_duration = None

        for c_name in inspection_df.columns.values:

            if c_name in column_names:
                # TODO: Allow user to select another parameter, median used by default
                new_data[c_name] = [inspection_df[c_name].median()]

            elif c_name == "end_datetime":

                if "start_datetime" in inspection_df.columns.values:
                    inspection_start = pd.to_datetime(inspection_df["start_datetime"]).min()

                if "end_datetime" in inspection_df.columns.values:
                    inspection_end = pd.to_datetime(inspection_df["end_datetime"]).max()

                if inspection_start and inspection_end:
                    inspection_duration = inspection_end - inspection_start

            elif c_name in unashable_columns.index.values:
                if c_name == "hwinfo__cpu_features__flags":
                    initial_set = set(inspection_df[c_name][0])
                    difference = False
                    for flags_counter in range(1, len(inspection_df[c_name])):
                        if initial_set - set(inspection_df[c_name][flags_counter]):
                            difference = True

                    if not difference:
                        new_data[c_name] = [inspection_df[c_name][0]]
                    else:
                        new_data[c_name] = np.nan

                else:
                    values_column = inspection_df[c_name].apply(str).value_counts()
                    _LOGGER.debug(f"Skipped unashable column {c_name}: {values_column}")
                    new_data[c_name] = np.nan
            else:
                if len(inspection_df[c_name].unique()) == 1:
                    new_data[c_name] = [inspection_df[c_name].iloc[0]]
                else:
                    _LOGGER.debug(f"Skipped multiple values column: {c_name}")
                    new_data[c_name] = np.nan

        if inspection_duration:
            inspection_duration = inspection_duration.seconds

        new_data["inspection_start"] = [inspection_start]
        new_data["inspection_end"] = [inspection_end]
        new_data["inspection_duration"] = [inspection_duration]
        new_data["inspection_batch"] = [inspection_df.shape[0]]

        columns = [c for c in inspection_df.columns.values] + extra_columns
        return pd.DataFrame(new_data, columns=columns)

    @classmethod
    def create_inspections_dataframe(
        cls,
        processed_inspection_runs: Dict[str, pd.DataFrame],
        include_statistics: bool = False,
        performance_values: List[str] = ["elapsed_time", "rate"],
        parameter_for_statistics: str = "elapsed_time",
    ) -> pd.DataFrame:
        """Create final pd.DataFrame from processed inspections runs after evaluating statistics.

        :param processed_inspection_runs: dict with inspection results per inspection ID
        provided by `process_inspection_runs`.
        :param include_statistics: bool to decide if statistics are included in the dataframe
        :param parameter_for_statistics: parameter on which statistics are applied
        (it is used only when include_statistics=True)
        """
        if not processed_inspection_runs:
            _LOGGER.warning("No inspections runs have been received, no analysis can be performed.")
            return pd.DataFrame()

        if any(p_check not in cls._INSPECTION_PERFORMANCE_VALUES for p_check in performance_values):
            raise Exception(
                f"Performance parameters selected {performance_values}"
                f" are not all registered: {cls._INSPECTION_PERFORMANCE_VALUES}",
            )

        row_number = 0
        extracted_columns = []
        flags_columns = []

        for dataframe in processed_inspection_runs.values():

            for column in dataframe.columns.values:
                if column not in extracted_columns:
                    extracted_columns.append(column)

            for flags in dataframe["hwinfo__cpu_features__flags"].values:
                for flag in flags:
                    if f"flag__{flag}" not in flags_columns:
                        flags_columns.append(f"flag__{flag}")

        for flag_column in flags_columns:
            extracted_columns.append(flag_column)

        extra_columns = ["inspection_start", "inspection_end", "inspection_duration", "inspection_batch"]
        for extra_column in extra_columns:
            extracted_columns.append(extra_column)

        main_inspection_df = pd.DataFrame(columns=extracted_columns)

        column_names = [
            cls._INSPECTION_PERFORMANCE_VALUES[p_value] for p_value in performance_values
        ] + cls._INSPECTION_USAGE_VALUES

        for dataframe in processed_inspection_runs.values():

            new_df = cls.evaluate_statistics_on_inspection_df(
                inspection_df=dataframe,
                column_names=column_names,
                extra_columns=extra_columns,
            )

            for flags_ in dataframe["hwinfo__cpu_features__flags"].values:
                for flag_ in flags_:
                    new_df[f"flag__{flag_}"] = True

            main_inspection_df.loc[row_number] = new_df.iloc[0]
            row_number += 1

        if include_statistics:
            inspections_statistics_dataframe = AmunInspectionsStatistics.create_inspections_statistics_dataframe(
                processed_inspection_runs=processed_inspection_runs,
                parameters=[parameter_for_statistics],
            )
            return pd.merge(main_inspection_df, inspections_statistics_dataframe, on="inspection_document_id")

        return main_inspection_df

    @staticmethod
    def create_python_package_df(
        inspections_df: pd.DataFrame,
    ) -> Tuple[pd.DataFrame, Dict[str, Any], pd.DataFrame]:
        """Create DataFrame with only python packages present in software stacks.

        :param inspection_df: df of inspections results provided by `create_inspections_dataframe`.
        """
        python_packages_versions: Dict[str, Any] = {}
        python_packages_versions_plot: Dict[str, Any] = {}
        python_packages_names = []

        sws_df = inspections_df[[col for col in inspections_df.columns.values if "__index" in col]]

        for c_name in sws_df.columns.values:
            if "__index" in c_name:
                python_packages_names.append(c_name.split("__")[2])

        columns_packages = []
        for package in python_packages_names:
            columns_packages.append("".join(["requirements_locked__default__", package, "__index"]))
            columns_packages.append("".join(["requirements_locked__default__", package, "__version"]))

        for index, row in inspections_df[columns_packages].iterrows():

            for package in python_packages_names:
                version = row["".join(["requirements_locked__default__", package, "__version"])]
                index = row["".join(["requirements_locked__default__", package, "__index"])]

                if pd.isnull(version):
                    if package not in python_packages_versions.keys():
                        python_packages_versions[package] = []
                        python_packages_versions_plot[package] = []

                    python_packages_versions[package].append("")
                    python_packages_versions_plot[package].append("")

                else:
                    if package not in python_packages_versions.keys():
                        python_packages_versions[package] = []
                        python_packages_versions_plot[package] = []

                    python_packages_versions[package].append(f"{package}-{version.replace('==', '')}-{index}")
                    python_packages_versions_plot[package].append(version.replace("==", ""))

        return (
            pd.DataFrame(python_packages_versions),
            python_packages_versions,
            pd.DataFrame(python_packages_versions_plot),
        )

    @classmethod
    def create_final_dataframe(
        cls,
        inspections_df: pd.DataFrame,
        filters_for_identifiers: Optional[List[str]] = None,
        include_statistics: bool = False,
        use_only_versions: bool = False,
    ) -> pd.DataFrame:
        """Create final dataframe with all information required for plots.

        :param inspection_df: df of inspections results provided by `create_inspections_dataframe`.
        :param filters_for_identifiers: list of words to standardize identifiers.
        """
        if inspections_df.empty:
            _LOGGER.exception("Inspections dataframe is empty!")
            return pd.DataFrame()

        python_packages_dataframe, packages_versions_indexes, versions = cls.create_python_package_df(
            inspections_df=inspections_df,
        )

        label_encoder = LabelEncoder()

        if not use_only_versions:
            processed_string_result = copy.deepcopy(packages_versions_indexes)
        else:
            processed_string_result = copy.deepcopy(versions)

        sws_encoded = []
        for index, row in python_packages_dataframe.iterrows():
            sws_string = "<br>".join(["".join(pkg) for pkg in row.values if pkg != ""])
            hash_object = hashlib.sha256(bytes(sws_string, "raw_unicode_escape"))
            hex_dig = hash_object.hexdigest()
            sws_encoded.append([row.values, sws_string, hex_dig])

        re_encoded = []

        for index, row in inspections_df[
            ["os_release__id", "os_release__version_id", "requirements_locked___meta__requires__python_version"]
        ].iterrows():
            re_values = [re for re in row.values]
            re_values[2] = "".join(["py", "".join(re_values[2].split("."))])
            re_string = "-".join(re_values)
            hash_object = hashlib.sha256(bytes(re_string, "raw_unicode_escape"))
            hex_dig = hash_object.hexdigest()
            re_encoded.append([row.values, re_string, hex_dig])

        # Software Stack encoding
        processed_string_result["packages_list"] = [pp[0] for pp in sws_encoded]
        processed_string_result["sws_string"] = [pp[1] for pp in sws_encoded]
        processed_string_result["sws_hash_id"] = [pp[2] for pp in sws_encoded]

        sws_hash_id_values = array([pp[2] for pp in sws_encoded])

        integer_sws_hash_id_values_encoded = label_encoder.fit_transform(sws_hash_id_values)
        processed_string_result["sws_hash_id_encoded"] = integer_sws_hash_id_values_encoded

        # Runtime Environment:
        # Solver: OSName-OSVersion-PythonInterpreterVersion
        processed_string_result["solver"] = [pp[0] for pp in re_encoded]

        processed_string_result["os_name"] = [solver[0] for solver in processed_string_result["solver"]]
        processed_string_result["os_version"] = [solver[1] for solver in processed_string_result["solver"]]
        processed_string_result["python_interpreter"] = [solver[2] for solver in processed_string_result["solver"]]
        processed_string_result["solver_string"] = [pp[1] for pp in re_encoded]
        processed_string_result["solver_hash_id"] = [pp[2] for pp in re_encoded]

        processed_string_result["base"] = [
            cpu_family[0] for cpu_family in inspections_df[["specification_base"]].values
        ]

        # Hardware:
        # CPU
        processed_string_result["cpu_brand"] = [
            cpu_brand[0] for cpu_brand in inspections_df[["hwinfo__cpu_info__brand_raw"]].values
        ]
        processed_string_result["cpu_family"] = [
            cpu_family[0] for cpu_family in inspections_df[["runtime_environment__hardware__cpu_family"]].values
        ]
        processed_string_result["cpu_model"] = [
            cpu_model[0] for cpu_model in inspections_df[["runtime_environment__hardware__cpu_model"]].values
        ]
        processed_string_result["number_cpus"] = [
            number_cpus[0] for number_cpus in inspections_df[["run__requests__cpu"]].values
        ]
        # GPU
        processed_string_result["cuda_version"] = [
            cuda_version[0] for cuda_version in inspections_df[["runtime_environment__cuda_version"]].values
        ]

        # PI
        processed_string_result["pi_name"] = [pi_n[0] for pi_n in inspections_df[["stdout__name"]].values]
        processed_string_result["pi_component"] = [pi_c[0] for pi_c in inspections_df[["stdout__component"]].values]
        processed_string_result["pi_sha256"] = [pi_c[0] for pi_c in inspections_df[["script_sha256"]].values]

        # PI performance results
        processed_string_result["elapsed_time"] = [
            r_e[0] for r_e in inspections_df[["stdout__@result__elapsed"]].values
        ]
        processed_string_result["rate"] = [r_r[0] for r_r in inspections_df[["stdout__@result__rate"]].values]

        processed_string_result["inspection_document_id"] = [
            i[0] for i in inspections_df[["inspection_document_id"]].values
        ]

        final_df = pd.DataFrame(processed_string_result)

        standardized_identifiers = []

        if not filters_for_identifiers:
            filters_for_identifiers = []

        for _, row in inspections_df[["inspection_document_id", "identifier"]].iterrows():
            inspection_document_id = row["inspection_document_id"]
            identifier = row["identifier"]

            selected_identifer_ = identifier

            if not identifier:
                selected_identifer_ = inspection_document_id

            identifier_filter = "-".join(
                [word for word in selected_identifer_.split("-") if word not in filters_for_identifiers],
            )

            standardized_identifiers.append(identifier_filter)

        final_df["identifier"] = inspections_df["identifier"]
        final_df["standardized_identifier"] = standardized_identifiers

        final_df["start_datetime"] = inspections_df["inspection_start"]
        final_df["end_datetime"] = inspections_df["inspection_end"]

        final_df["total_duration"] = inspections_df["inspection_duration"]
        final_df["inspection_batch"] = inspections_df["inspection_batch"]

        if include_statistics:
            final_df["statistical_parameter"] = inspections_df["statistical_parameter"]
            final_df["std"] = inspections_df["std"]
            final_df["std_error"] = inspections_df["std_error"]
            final_df["mean"] = inspections_df["mean"]
            final_df["median"] = inspections_df["median"]
            final_df["q1"] = inspections_df["q1"]
            final_df["q3"] = inspections_df["q3"]
            final_df["iqr"] = inspections_df["iqr"]
            final_df["min"] = inspections_df["min"]
            final_df["max"] = inspections_df["max"]
            final_df["cov"] = inspections_df["cov"]
            final_df["covm"] = inspections_df["covm"]
            final_df["skew"] = inspections_df["skew"]

        return final_df

    @staticmethod
    def _convert_package_list_to_string(packages_version: List[str]) -> str:
        """Convert package list to str."""
        package_query = "["
        package_n = 1

        for package_name in packages_version:
            if package_n == 1:
                package_query += f'"{package_name}"'
            else:
                package_query += f', "{package_name}"'
            package_n += 1
        package_query += "]"

        return package_query

    @classmethod
    def filter_final_inspections_dataframe(
        cls,
        final_inspections_df: pd.DataFrame,
        inspection_document_ids: Optional[List[str]] = None,
        r_inspection_document_ids: Optional[List[str]] = None,
        standardized_ids: Optional[List[str]] = None,
        pi_name: Optional[List[str]] = None,
        pi_component: Optional[List[str]] = None,
        base: Optional[List[str]] = None,
        os_name: Optional[List[str]] = None,
        os_version: Optional[List[str]] = None,
        python_interpreter: Optional[List[str]] = None,
        cpu_family: Optional[List[str]] = None,
        cpu_model: Optional[List[str]] = None,
        cpus_number: Optional[List[str]] = None,
        packages: Optional[Dict[str, Any]] = None,
    ) -> pd.DataFrame:
        """Filter final inspections dataframe for plots.

        :param final_inspections_df: df for plots provided by `create_final_dataframe` or its subset.
        :param inspection_document_ids: fiter by inspection ids
        :param r_inspection_document_ids: remove by inspection ids
        :param standardized_ids: filter by standardized ids
        :param pi_name: fiter by performance indicator names (e.g PIMatmul)
        :param pi_component: filter by performance indicator components (e.g. tensorflow)
        :param base: filter by base images used e.g. quay.io/thoth-station/s2i-thoth-ubi8-py36
        :param os_name: filter by Operating System names e.g rhel
        :param os_version: filter by Operatin System versions e.g 8
        :param python_interpreter: filter by Python interpreters e.g 3.6
        :param cpu_family: filter by CPU family e.g 6
        :param cpu_model: filter by CPU model e.g. 85
        :param cpus_number: filter by number of CPUs e.g. 2
        :param packages: filter by packages in software stack: for each package {"name": ["name-version-index"]}.
        """
        if not final_inspections_df.shape[0]:
            _LOGGER.info("DataFrame provided is empty, nothing can be filtered.")

        filtered_df = final_inspections_df.copy()
        # Inspection IDs
        if inspection_document_ids:
            filtered_df.query("`inspection_document_id` == @inspection_document_ids", inplace=True)

        if r_inspection_document_ids:
            filtered_df.query("`inspection_document_id` != @r_inspection_document_ids", inplace=True)

        if standardized_ids:
            filtered_df.query("`standardized_identifier` == @standardized_ids", inplace=True)

        # Software stack
        if packages:
            counter = 1
            for package in packages:
                packages_version = packages[package]
                package_query = cls._convert_package_list_to_string(packages_version=packages_version)
                if counter == 1:
                    dynamic_query = f"`{package}` == {package_query}"
                else:
                    dynamic_query += f" and `{package}` == {package_query}"

                counter += 1
            filtered_df.query(dynamic_query, inplace=True)

        # Runtime Environment
        if base:
            filtered_df.query("base == @base", inplace=True)

        # Operating System
        if os_name:
            filtered_df.query("os_name == @os_name", inplace=True)

        if os_version:
            filtered_df.query("os_version == @os_version", inplace=True)

        # Python Interpreter
        if python_interpreter:
            filtered_df.query("python_interpreter == @python_interpreter", inplace=True)

        # Hardware
        if cpu_family:
            filtered_df.query("cpu_family == @cpu_family", inplace=True)

        if cpu_model:
            filtered_df.query("cpu_model == @cpu_model", inplace=True)

        if cpus_number:
            filtered_df.query("number_cpus == @cpus_number", inplace=True)

        # Performance Indicator (PI)
        if pi_name:
            filtered_df.query("pi_name == @pi_name", inplace=True)

        if pi_component:
            filtered_df.query("pi_component == @pi_component", inplace=True)

        if not filtered_df.shape[0]:
            _LOGGER.info("There are no results for the filters selected. Please change filters.")

        _LOGGER.info(f"Number of software stacks identified: {filtered_df.shape[0]}")

        return filtered_df

    @staticmethod
    def create_plot_results_summary(
        final_inspections_df: pd.DataFrame,
        performance_packages: List[str],
        include_statistics: bool = False,
    ) -> pd.DataFrame:
        """Show performance results summary.

        :param final_inspections_df: df for plots provided by `create_final_dataframe`.
        :param performance_packages: list of packages names
        :param include_statistics: include statistics in summary
        """
        identifier = ["inspection_document_id", "identifier", "standardized_identifier"]
        solver = ["os_name", "os_version", "base", "python_interpreter"]
        hardware = ["cpu_brand", "cpu_family", "cpu_model", "number_cpus"]
        runtime_environment = solver + hardware

        pi_info = ["pi_name"] + ["elapsed_time", "rate"]

        if include_statistics:
            statistics = [
                "statistical_parameter",
                "std",
                "std_error",
                "mean",
                "median",
                "q1",
                "q3",
                "iqr",
                "max",
                "min",
                "cov",
                "covm",
                "skew",
            ]
            return final_inspections_df[identifier + performance_packages + runtime_environment + pi_info + statistics]

        return final_inspections_df[identifier + performance_packages + runtime_environment + pi_info]


class AmunInspectionsStatistics:
    """Class of methods used to create statistics from Amun Inspections Runs."""

    _INSPECTION_MAPPING_PARAMETERS = {
        "elapsed_time": "stdout__@result__elapsed",
        "rate": "stdout__@result__rate",
        "utime": "usage__ru_utime",
        "stime": "usage__ru_stime",
        "nvcsw": "usage__ru_nvcsw",
        "nivcsw": "usage__ru_nivcsw",
    }

    @classmethod
    def _create_inspection_parameters_dataframe(
        cls,
        inspections_df: pd.DataFrame,
        parameters: List[str],
    ) -> pd.DataFrame:
        """Create pd.DataFrame of selected parameters from inspections_df.

        :param inspections_df: single inspection results  dataframe
        taken by `AmunInspections.process_inspection_runs` dictionary.
        :param parameters: inspection parameters used in the statistical analysis
        """
        renamed_columns = {cls._INSPECTION_MAPPING_PARAMETERS[parameter]: parameter for parameter in parameters}
        renamed_columns["stdout__name"] = "pi_name"

        filters = ["inspection_number", "inspection_document_id", "stdout__name"] + [
            cls._INSPECTION_MAPPING_PARAMETERS[parameter] for parameter in parameters
        ]
        subset_df = inspections_df[filters]
        subset_df.rename(columns=renamed_columns, inplace=True)

        return subset_df

    @classmethod
    def create_inspections_statistics_dataframe(
        cls,
        processed_inspection_runs: Dict[str, Any],
        parameters: List[str],
    ) -> pd.DataFrame:
        """Evaluate statistical quantities of each parameter selected for inspection results.

        :param processed_inspection_runs: dict with inspection results per inspection ID
        provided by `AmunInspections.process_inspection_runs`.
        :param parameters: inspection parameters used in the statistical analysis
        """
        results: List[Dict[str, Any]] = []

        for inspection_document_id in processed_inspection_runs:
            inspection_id_results_df = processed_inspection_runs[inspection_document_id]

            inspection_parameters_df = cls._create_inspection_parameters_dataframe(
                inspections_df=inspection_id_results_df,
                parameters=parameters,
            )

            for inspection_parameter in parameters:
                std = inspection_parameters_df[inspection_parameter].std()
                std_error = std / np.sqrt(inspection_parameters_df[inspection_parameter].shape[0])
                mean = inspection_parameters_df[inspection_parameter].mean()
                median = inspection_parameters_df[inspection_parameter].median()
                q1 = inspection_parameters_df[inspection_parameter].quantile([0.25])
                q3 = inspection_parameters_df[inspection_parameter].quantile([0.75])
                q1 = q1.iloc[[0.25]].values[0]
                q3 = q3.iloc[[0.75]].values[0]
                iqr = q3 - q1
                maxr = inspection_parameters_df[inspection_parameter].max()
                minr = inspection_parameters_df[inspection_parameter].min()
                cov = std / mean
                covm = iqr / median
                skew = inspection_parameters_df[inspection_parameter].skew()

                results.append(
                    {
                        "inspection_document_id": inspection_document_id,
                        "pi_name": inspection_parameters_df["pi_name"].unique()[0],
                        "statistical_parameter": inspection_parameter,
                        "std": std,
                        "std_error": std_error,
                        "mean": mean,
                        "median": median,
                        "q1": q1,
                        "q3": q3,
                        "iqr": iqr,
                        "max": maxr,
                        "min": minr,
                        "cov": cov,
                        "covm": covm,
                        "skew": skew,
                    },
                )

        inspections_statistics_dataframe = pd.DataFrame(results)

        return inspections_statistics_dataframe


class AmunInspectionsFailedSummary:
    """Class of methods used to compare failed with successfull inspections from Amun Inspections Runs."""

    @staticmethod
    def show_software_stack_differences(
        inspections_df: pd.DataFrame,
        failed_inspections_df: pd.DataFrame,
    ) -> pd.DataFrame:
        """Create summary report of the difference in the layers identified.

        :param inspection_df: df of inspections results provided by `AmunInspections.create_inspections_dataframe`.
        :param failed_inspections_df: df of failed inspections results
        provided by `AmunInspections.create_inspections_dataframe`.
        """
        results: List[Dict[str, Any]] = []
        if inspections_df.empty or failed_inspections_df.empty:
            _LOGGER.warning("No inspections runs have been received, no failures summary can be produced.")
            return pd.DataFrame(results)

        python_packages_dataframe, _, _ = AmunInspections.create_python_package_df(inspections_df=inspections_df)
        packages = set(python_packages_dataframe.columns.values)

        python_packages_dataframe_failed, _, _ = AmunInspections.create_python_package_df(
            inspections_df=failed_inspections_df,
        )
        packages_from_failed = set(python_packages_dataframe_failed.columns.values)

        total_packages = packages.union(packages_from_failed)

        for package in sorted(list(total_packages)):

            evaluated = 0

            success: Iterable[Any] = set()
            if package in python_packages_dataframe.columns.values:
                success = python_packages_dataframe[package].unique()
                evaluated += 1

            failed: Iterable[Any] = set()
            if package in python_packages_dataframe.columns.values:
                failed = python_packages_dataframe_failed[package].unique()
                evaluated += 1

            if evaluated == 2:
                difference: Iterable[Any] = set(failed) - set(success)
                common = set(failed) & set(success)

            results.append(
                {
                    "package": package,
                    "versions_in_successfull": sorted(success),
                    "versions_in_failed": sorted(failed),
                    "versions_in_failed_only": sorted(difference),
                    "versions_common": sorted(common),
                },
            )

        return pd.DataFrame(results)


class AmunInspectionsSummary:
    """Class of methods used to create summary from Amun Inspections Runs."""

    _INSPECTION_REPORT_FEATURES = {
        "hardware": {"title": "Hardware", "values": ["platform", "processor", "flags", "ncpus", "info"]},
        "base_image": {"title": "Operating System", "values": ["base_image", "number_cpus_run"]},
        "software_stack": {"title": "Software Stack", "values": ["requirements_locked"]},
        "pi": {"title": "Performance Indicator", "values": ["pi"]},
        "exit_codes": {"title": "Exit Code", "values": ["exit_code"]},
    }

    _INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING = {
        "platform": {"description": "Platform", "values": ["hwinfo__platform"]},
        "processor": {"description": "Processor", "values": ["cpu_type__is", "cpu_type__has"]},
        "flags": {"description": "Flags", "values": ["flag__"]},
        "ncpus": {"description": "Number of CPUs", "values": ["hwinfo__cpu_type__ncpus"]},
        "info": {
            "description": "General info",
            "values": [
                "runtime_environment__hardware__cpu_family",
                "runtime_environment__hardware__cpu_model",
                "hwinfo__cpu_info__brand_raw",
                "runtime_environment__cuda_version",
            ],
        },
        "requirements_locked": {
            "description": "Packages",
            "values": ["requirements_locked__default", "requirements_locked___meta"],
        },
        "base_image": {
            "description": "Base Image",
            "values": ["os_release__name", "os_release__version", "specification_base"],
        },
        "number_cpus_run": {"description": "CPUs during run", "values": ["run__requests__cpu"]},
        "pi": {
            "description": "",
            "values": ["script_sha256", "@parameters", "stdout__name", "stdout__component", "batch_size"],
        },
        "exit_code": {"description": "", "values": ["exit_code"]},
    }

    @classmethod
    def _discover_unique_values(cls, objects: pd.DataFrame) -> pd.DataFrame:
        """Discover unique objects per context."""
        from deepdiff import DeepDiff  # For Deep Difference of 2 objects

        unique_objects = []
        first = objects.iloc[0].to_dict()
        unique_objects.append(objects.iloc[0].to_dict())

        for number in range(1, objects.shape[0]):
            new = objects.iloc[number].to_dict()
            ddiff = DeepDiff(first, new, ignore_order=True)

            if ddiff:
                unique = True
                for obj in unique_objects:
                    sddiff = DeepDiff(obj, new, ignore_order=True)
                    if not sddiff:
                        unique = False

                if unique:
                    unique_objects.append(new)

        return pd.DataFrame(unique_objects)

    @classmethod
    def produce_summary_report(
        cls,
        inspections_df: pd.DataFrame,
        is_markdown: Optional[bool] = False,
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """Create summary report of the difference in the layers identified.

        :param inspection_df: df of inspections results provided by `AmunInspections.create_inspections_dataframe`.
        """
        report_results: Dict[str, Any] = {}
        md_report_complete = ""

        if inspections_df.empty:
            _LOGGER.warning("No inspections runs have been received, no report summary can be produced.")
            return report_results, md_report_complete

        for feature in cls._INSPECTION_REPORT_FEATURES:
            md_report_complete += f"\n\n {cls._INSPECTION_REPORT_FEATURES[feature]['title']}"
            report_results[feature] = {}

            for report_part in cls._INSPECTION_REPORT_FEATURES[feature]["values"]:
                md_report_complete += (
                    f"\n\n {cls._INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING[report_part]['description']}"
                )
                cols = cls._INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING[report_part]["values"]
                extracted = inspections_df[[col for col in inspections_df.columns if any(c in col for c in cols)]]
                extracted = extracted.fillna("nan")
                unique_extracted = cls._discover_unique_values(extracted)

                if feature == "software_stack":
                    unique_extracted = unique_extracted[
                        [
                            col
                            for col in unique_extracted.columns.values
                            if any(s in col for s in ["__version", "__index", "__meta"])
                        ]
                    ]
                report_results[feature][report_part] = unique_extracted
                md_report_complete += "\n\n" + unique_extracted.transpose().to_markdown()

        if not is_markdown:
            return report_results, md_report_complete

        return report_results, md_report_complete
