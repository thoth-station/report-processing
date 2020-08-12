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
from typing import List, Optional, Tuple, Dict, Any

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

    _INSPECTION_PERFORMANCE_VALUES = ["stdout__@result__elapsed", "stdout__@result__rate"]

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
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = False,
        repo_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Aggregate results stored on Ceph or locally from repo for Thoth components reports.

        :param store_files: files to be retrieved from the Store for each result, if None all files are retrieved.
        :param inspections_identifiers: Inspection identifiers in inspection IDs.
        :param limit_results: reduce the number of reports ids considered to `max_ids`.
        :param max_ids: maximum number of reports ids considered.
        :param is_local: flag to retrieve the dataset locally (if not uses Ceph S3 (credentials are required)).
        :param repo_path: required if you want to retrieve the dataset locally and `is_local` is set to True.
        """
        if store_files:
            if any(store_file not in ThothAmunInspectionFileStoreEnum.__members__ for store_file in store_files):
                raise ThothNotKnownResultStore(
                    f"InspectionStore does not contain some of the files listed: {store_files}."
                    f"InspectionStore: {ThothAmunInspectionFileStoreEnum.__members__.keys()}"
                )

        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids}!")

        files: Dict[str, Any] = {}

        if not store_files:
            store_files = ["results", "specification", "hardware_info"]

        if is_local:
            files, counter = cls._aggregate_thoth_results_from_local(
                repo_path=repo_path,
                inspections_identifiers=inspections_identifiers,
                files=files,
                limit_results=limit_results,
                max_ids=max_ids,
                store_files=store_files,
            )

        else:
            files, counter = cls._aggregate_thoth_results_from_ceph(
                store_files=store_files,
                inspections_identifiers=inspections_identifiers,
                files=files,
                limit_results=limit_results,
                max_ids=max_ids,
            )

        _LOGGER.info("Number of files retrieved is: %r" % counter)

        return files

    @classmethod
    def _aggregate_thoth_results_from_local(
        cls,
        files: Dict[str, Any],
        store_files: Optional[List[str]] = None,
        inspections_identifiers: Optional[List[str]] = None,
        repo_path: Optional[Path] = None,
        limit_results: bool = False,
        max_ids: int = 5,
        is_multiple: Optional[bool] = None,
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from local repo."""
        _LOGGER.info(f"Retrieving dataset at path... {repo_path}")
        if not repo_path:
            _LOGGER.warning(f"No Path has been provided to retrieve data locally.")
            return files, 0

        if not repo_path.exists():
            raise ThothMissingDatasetAtPath(f"There is no dataset at this path: {repo_path}.")

        counter = 0

        # Iterate through inspection IDs
        for result_path in repo_path.iterdir():
            inspection_document_id = result_path.name

            if not inspections_identifiers or any(
                identifier in inspection_document_id for identifier in inspections_identifiers
            ):
                _LOGGER.info(f"Considering inspection ID... {inspection_document_id}")

                retrieved_files: List[Dict[str, Any]] = []

                # Iterate through inspection results number
                for inspection_number_path in Path(f"{result_path}/results").iterdir():
                    _LOGGER.info(
                        f"Considering inspection ID {inspection_document_id} number... {inspection_number_path.name}"
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

                    retrieved_files.append(file_info)

                files[inspection_document_id] = {"results": retrieved_files}

                if retrieved_files:
                    if store_files and ThothAmunInspectionFileStoreEnum.specification.name in store_files:

                        with open(f"{result_path}/build/specification", "r") as specification_file:
                            inspection_specification_document = json.load(specification_file)

                            files[inspection_document_id]["specification"] = inspection_specification_document

                            modified_results = []
                            for result in files[inspection_document_id]["results"]:
                                result["requirements"] = inspection_specification_document["python"]["requirements"]

                                requirements_locked = cls._parse_requirements_locked(
                                    requirements_locked=inspection_specification_document["python"][
                                        "requirements_locked"
                                    ]
                                )
                                result["result"]["requirements_locked"] = requirements_locked

                                modified_results.append(result)

                            files[inspection_document_id] = {"results": modified_results}

                    if store_files and ThothAmunInspectionFileStoreEnum.build_logs.name in store_files:

                        with open(f"{result_path}/build/log", "r") as build_logs_type:
                            inspection_build_logs = build_logs_type.read()

                            files[inspection_document_id]["build_logs"] = inspection_build_logs

                    counter += 1

                if limit_results:
                    if counter == max_ids:
                        return files, counter

        return files, counter

    @classmethod
    def _aggregate_thoth_results_from_ceph(
        cls,
        files: Dict[str, Any],
        store_files: Optional[List[str]] = None,
        inspections_identifiers: Optional[List[str]] = None,
        limit_results: bool = False,
        max_ids: int = 5,
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from Ceph."""
        store_class_type = InspectionStore

        # Inspection ID counter
        inspection_counter = 0

        for inspection_document_id in store_class_type.iter_inspections():

            if not inspections_identifiers or any(
                identifier in inspection_document_id for identifier in inspections_identifiers
            ):
                inspection_store = InspectionStore(inspection_id=inspection_document_id)
                inspection_store.connect()

                _LOGGER.info(f"Document id: {inspection_document_id}")
                number_results = inspection_store.results.get_results_count()

                # Inspection ID result counter
                inspection_result_counter = 0

                if number_results > 0:

                    retrieved_files: List[Dict[str, Any]] = []

                    for inspection_result_number in range(number_results):

                        file_info: Dict[str, Any] = {}

                        try:

                            if store_files and ThothAmunInspectionFileStoreEnum.results.name in store_files:
                                inspection_result_document = inspection_store.results.retrieve_result(
                                    inspection_result_number
                                )

                                file_info["result"] = inspection_result_document
                                file_info["result"]["inspection_document_id"] = inspection_document_id

                            if store_files and ThothAmunInspectionFileStoreEnum.hardware_info.name in store_files:
                                inspection_hw_info = inspection_store.results.retrieve_hwinfo(
                                    item=inspection_result_number
                                )

                                file_info["hwinfo"] = inspection_hw_info

                            if store_files and ThothAmunInspectionFileStoreEnum.job_logs.name in store_files:
                                inspection_job_logs = inspection_store.results.retrieve_log()

                                file_info["job_logs"] = inspection_job_logs

                            inspection_result_counter += 1

                            _LOGGER.info(
                                "Documents id %r results number retrieved: %r",
                                inspection_document_id,
                                inspection_result_number,
                            )

                        except Exception as inspection_exception:
                            _LOGGER.exception(
                                f"Exception during retrieval of inspection id {inspection_document_id} results"
                                f"n.{inspection_result_number}: {inspection_exception}"
                            )
                            pass

                        retrieved_files.append(file_info)

                if inspection_result_counter > 0:

                    files[inspection_document_id] = {"results": retrieved_files}

                    try:
                        if store_files and ThothAmunInspectionFileStoreEnum.specification.name in store_files:
                            inspection_specification_document = inspection_store.retrieve_specification()

                            files[inspection_document_id]["specification"] = inspection_specification_document

                            modified_results = []
                            for result in files[inspection_document_id]["results"]:
                                result["requirements"] = inspection_specification_document["python"]["requirements"]

                                requirements_locked = cls._parse_requirements_locked(
                                    requirements_locked=inspection_specification_document["python"][
                                        "requirements_locked"
                                    ]
                                )
                                result["result"]["requirements_locked"] = requirements_locked

                                modified_results.append(result)

                            files[inspection_document_id] = {"results": modified_results}

                        if store_files and ThothAmunInspectionFileStoreEnum.build_logs.name in store_files:
                            inspection_build_logs = inspection_store.build.retrieve_log()

                            files[inspection_document_id]["build_logs"] = inspection_build_logs

                        inspection_counter += 1

                        _LOGGER.info("Documents id retrieved: %r", inspection_counter)

                        if limit_results:
                            if inspection_counter == max_ids:
                                return files, inspection_counter

                    except Exception as inspection_exception:
                        _LOGGER.exception(
                            f"Exception during retrieval of inspection info for"
                            f"inspection id {inspection_document_id}: {inspection_exception}"
                        )
                        pass

                else:
                    _LOGGER.warning(f"No inspection results identified for inspection ID: {inspection_document_id}")

        return files, inspection_counter

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
    def process_inspection_runs(cls, inspection_runs: Dict[str, Any]) -> Dict[str, pd.DataFrame]:
        """Process inspection runs into pd.DataFrame for each inspection ID.

        :param inspection_runs: aggregated data provided by `aggregate_thoth_inspections_runs`.
        """
        processed_inspection_runs: Dict[str, pd.DataFrame] = {}

        if not inspection_runs:
            _LOGGER.warning("Empty iterable provided.")
            return processed_inspection_runs

        for inspection_id, inspection_run in inspection_runs.items():

            inspection_run_df = cls.process_inspection_run(inspection_run=inspection_run)

            if inspection_run_df.shape[0] > 1:
                processed_inspection_runs[inspection_id] = inspection_run_df

        return processed_inspection_runs

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
    def evaluate_statistics_on_inspection_df(inspection_df: pd.DataFrame, column_names: List[str]) -> pd.DataFrame:
        """Evaluate statistics on performance values selected from Dataframe columns."""
        unashable_columns = inspection_df.applymap(lambda x: isinstance(x, dict) or isinstance(x, list)).all()[
            lambda x: x == True  # noqa
        ]
        new_data = {}
        for c_name in inspection_df.columns.values:

            if c_name in column_names:
                new_data[c_name] = [inspection_df[c_name].median()]

            elif c_name in unashable_columns.index.values:
                values_column = inspection_df[c_name].apply(str).value_counts()
                _LOGGER.debug(f"Skipped unashable column {c_name}: {values_column}")
            else:
                if len(inspection_df[c_name].unique()) == 1:
                    new_data[c_name] = [inspection_df[c_name].iloc[0]]
                else:
                    _LOGGER.debug(f"Skipped multiple values column: {c_name}")

        return pd.DataFrame(new_data, index=[0], columns=inspection_df.columns.values)

    @classmethod
    def create_inspections_dataframe(cls, processed_inspection_runs: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        """Create final pd.DataFrame from processed inspections runs after evaluating statistics.

        :param processed_inspection_runs: dict with inspection results per inspection ID
        provided by `process_inspection_runs`.
        """
        index = 0

        extracted_columns = []

        for dataframe in processed_inspection_runs.values():

            for column in dataframe.columns.values:
                if column not in extracted_columns:
                    extracted_columns.append(column)

        inspections_df = pd.DataFrame(columns=extracted_columns)

        column_names = cls._INSPECTION_PERFORMANCE_VALUES + cls._INSPECTION_USAGE_VALUES

        for dataframe in processed_inspection_runs.values():

            new_df = cls.evaluate_statistics_on_inspection_df(inspection_df=dataframe, column_names=column_names)
            inspections_df.loc[index] = new_df.iloc[0]
            index += 1

        return inspections_df

    @staticmethod
    def create_python_package_df(inspections_df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Create DataFrame with only python packages present in software stacks.

        :param inspection_df: df of inspections results provided by `create_inspections_dataframe`.
        """
        python_packages_versions: Dict[str, Any] = {}
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

                    python_packages_versions[package].append(("", "", ""))

                else:
                    if package not in python_packages_versions.keys():
                        python_packages_versions[package] = []

                    python_packages_versions[package].append((package, version, index))

        return pd.DataFrame(python_packages_versions), python_packages_versions

    @classmethod
    def create_final_dataframe(cls, inspections_df: pd.DataFrame) -> pd.DataFrame:
        """Create final dataframe with all information required for plots.

        :param inspection_df: df of inspections results provided by `create_inspections_dataframe`.
        """
        if inspections_df.empty:
            _LOGGER.exception("Inspections dataframe is empty!")
            return pd.DataFrame()

        python_packages_dataframe, packages_versions = cls.create_python_package_df(inspections_df=inspections_df)

        label_encoder = LabelEncoder()

        processed_string_result = copy.deepcopy(packages_versions)

        sws_encoded = []
        for index, row in python_packages_dataframe.iterrows():
            sws_string = "<br>".join(["".join(pkg) for pkg in row.values if pkg != ("", "", "")])
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
        # Hardware:
        processed_string_result["cpu_brand"] = [
            cpu_brand[0] for cpu_brand in inspections_df[["hwinfo__cpu_info__brand_raw"]].values
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

        final_df = pd.DataFrame(processed_string_result)

        final_df["inspection_id"] = inspections_df["inspection_document_id"]
        inspection_identifiers = [identifier.split("-")[1] for identifier in final_df["inspection_id"].values]
        final_df["identifier"] = inspection_identifiers

        return final_df

    @staticmethod
    def _filter_df(df: pd.DataFrame, *args: List[Any]) -> pd.DataFrame:
        """Filter Dataframe."""
        for f in args:
            for k, v in f:
                df = df[df[k] == v]
        return df

    @classmethod
    def filter_final_inspections_dataframe(
        cls,
        final_inspections_df: pd.DataFrame,
        pi_name: Optional[str] = None,
        pi_component: Optional[str] = None,
        solver: Optional[str] = None,
        packages: Optional[List[Tuple[str, str, str]]] = None,
    ) -> pd.DataFrame:
        """Filter final inspections dataframe for plots.

        :param final_inspections_df: df for plots provided by `create_final_dataframe`.
        :param pi_name: fiter by performance indicator name (e.g PIMatmul)
        :param pi_component: filter by performance indicator component (e.g. tensorflow)
        :param solver: filter by solver (rhel-8-py36)
        :param packages: filter by list of packages [(name, version, index)] in software stack.
        """
        if not final_inspections_df.shape[0]:
            _LOGGER.info("DataFrame provided is empty, nothing can be filtered.")

        filters: List[Tuple[str, Any]] = []

        if pi_name:
            filters.append(("pi_name", pi_name))

        if pi_component:
            filters.append(("pi_component", pi_component))

        if solver:
            filters.append(("solver_string", solver))

        if packages:
            for package in packages:
                filters.append((package[0], package))

        filtered_final_df = cls._filter_df(final_inspections_df, filters)

        if not filtered_final_df.shape[0]:
            _LOGGER.info("There are no results for the filters selected. Please change filters.")

        _LOGGER.info(f"Number of software stacks identified: {filtered_final_df.shape[0]}")

        return filtered_final_df

    @staticmethod
    def create_performance_results_summary(
        final_inspections_df: pd.DataFrame, performance_packages: List[str]
    ) -> pd.DataFrame:
        """Show performance results summary for python packages.

        :param final_inspections_df: df for plots provided by `create_final_dataframe`.
        :param performance_packages: list of packages names
        """
        solver = ["os_name", "os_version", "python_interpreter"]
        return final_inspections_df[
            ["identifier"] + performance_packages + ["cpu_brand"] + solver + ["elapsed_time", "rate"]
        ]


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
    def _create_inspection_parameters_dataframes(
        cls, processed_inspection_runs: Dict[str, Any], parameters: List[str]
    ) -> pd.DataFrame:
        """Create pd.DataFrame of selected parameters from inspections results to be used for statistics and error analysis.

        :param processed_inspection_runs: dict with inspection results per inspection ID
        provided by `Inspection.process_inspection_runs`.
        :param parameters: inspection parameters used in the analysis
        """
        inspection_parameters_df_dict = {}

        renamed_columns = {cls._INSPECTION_MAPPING_PARAMETERS[parameter]: parameter for parameter in parameters}
        renamed_columns["stdout__name"] = "pi_name"

        filters = ["inspection_number", "inspection_document_id", "stdout__name"] + [
            cls._INSPECTION_MAPPING_PARAMETERS[parameter] for parameter in parameters
        ]
        for inspection_id in processed_inspection_runs:
            inspection_id_results_df = processed_inspection_runs[inspection_id]

            subset_df = inspection_id_results_df[filters]
            subset_df.rename(columns=renamed_columns, inplace=True)

            inspection_parameters_df_dict[subset_df["inspection_document_id"].unique()[0]] = subset_df

        return inspection_parameters_df_dict

    @classmethod
    def create_inspections_statistics_dataframe(
        cls, processed_inspection_runs: Dict[str, Any], parameters: List[str]
    ) -> pd.DataFrame:
        """Evaluate statistical quantities of each parameter selected for inspection results.

        :param processed_inspection_runs: dict with inspection results per inspection ID
        provided by `Inspection.process_inspection_runs`.
        :param parameters: inspection parameters used in the statistical analysis
        """
        results: List[Dict[str, Any]] = []

        inspection_parameters_dfs = cls._create_inspection_parameters_dataframes(
            processed_inspection_runs=processed_inspection_runs, parameters=parameters
        )

        for inspection_id, inspection_parameters_df in inspection_parameters_dfs.items():
            for inspection_parameter in parameters:
                std_error = inspection_parameters_df[inspection_parameter].std() / np.sqrt(
                    inspection_parameters_df[inspection_parameter].shape[0]
                )
                std = inspection_parameters_df[inspection_parameter].std()
                median = inspection_parameters_df[inspection_parameter].median()
                q = inspection_parameters_df[inspection_parameter].quantile([0.25, 0.75])
                q1 = q.iloc[[0.25]].values[0]
                q3 = q.iloc[[0.75]].values[0]
                iqr = q3 - q1
                cv_mean = (
                    inspection_parameters_df[inspection_parameter].std()
                    / inspection_parameters_df[inspection_parameter].mean()
                    * 100
                )
                cv_median = (
                    inspection_parameters_df[inspection_parameter].std()
                    / inspection_parameters_df[inspection_parameter].median()
                    * 100
                )
                cv_q1 = inspection_parameters_df[inspection_parameter].std() / q1 * 100
                cv_q3 = inspection_parameters_df[inspection_parameter].std() / q3 * 100
                maxr = inspection_parameters_df[inspection_parameter].max()
                minr = inspection_parameters_df[inspection_parameter].min()

                results.append(
                    {
                        "inspection_id": inspection_id,
                        "pi_name": inspection_parameters_df["pi_name"].unique()[0],
                        "parameter": inspection_parameter,
                        "cv_mean": cv_mean,
                        "cv_median": cv_median,
                        "cv_q1": cv_q1,
                        "cv_q3": cv_q3,
                        "std_error": std_error,
                        "std": std,
                        "median": median,
                        "q1": q1,
                        "q3": q3,
                        "iqr": iqr,
                        "max": maxr,
                        "min": minr,
                    }
                )

        inspections_statistics_dataframe = pd.DataFrame(results)

        return inspections_statistics_dataframe


class AmunInspectionsSummary:
    """Class of methods used to create summary from Amun Inspections Runs."""

    _INSPECTION_REPORT_FEATURES = {
        "hardware": ["platform", "processor", "ncpus", "family"],
        "software_stack": ["requirements_locked"],
        "base_image": ["base_image"],
        "pi": ["script"],
        "exit_codes": ["exit_code"],
    }

    _INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING = {
        "platform": ["hwinfo__platform"],
        "processor": ["cpu_type__is", "cpu_type__has"],
        "ncpus": ["hwinfo__cpu_type__ncpus"],
        "family": ["runtime_environment__hardware__cpu_family", "hwinfo__cpu_info__brand_raw"],
        "requirements_locked": ["requirements_locked__default", "requirements_locked___meta"],
        "base_image": ["os_release__name", "os_release__version"],
        "script": ["script", "script_sha256", "@parameters", "stdout__name", "stdout__component"],
        "exit_code": ["exit_code"],
    }

    @staticmethod
    def _create_df_report(df: pd.DataFrame) -> pd.DataFrame:
        """Show unique values for each column in the dataframe."""
        dataframe_report = {}
        for column_name in df.columns.values:
            try:
                unique_values = [value for value in df[column_name].unique() if str(value) != "nan"]
                dataframe_report[column_name] = [unique_values]
            except Exception as exc:
                _LOGGER.warning(f"Could not evaluate unique values in column {column_name}: {exc}")
                dataframe_report[column_name] = [value for value in df[column_name].values if str(value) != "nan"]
                pass
        df_unique = pd.DataFrame(dataframe_report)
        return df_unique

    @classmethod
    def create_dfs_inspection_classes(
        cls, inspection_df: pd.DataFrame
    ) -> Tuple[Dict[str, pd.DataFrame], Dict[str, pd.DataFrame]]:
        """Create all inspection dataframes per class with unique values and complete values.

        :param inspection_df: df of inspections results provided by `Inspection.create_inspections_dataframe`.
        """
        class_inspection_dfs: Dict[str, Any] = {}
        class_inspection_dfs_unique: Dict[str, Any] = {}

        for class_inspection, class_features in cls._INSPECTION_REPORT_FEATURES.items():

            class_inspection_dfs[class_inspection] = {}
            class_inspection_dfs_unique[class_inspection] = {}

            if len(class_features) > 1:

                for feature in class_features:

                    if len(feature) > 1:
                        class_df = inspection_df[
                            [
                                col
                                for col in inspection_df.columns.values
                                if any(c in col for c in cls._INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING[feature])
                            ]
                        ]
                        class_inspection_dfs[class_inspection][feature] = class_df

                        class_df_unique = cls._create_df_report(class_df)
                        class_inspection_dfs_unique[class_inspection][feature] = class_df_unique
                    else:
                        class_df = inspection_df[
                            [
                                col
                                for col in inspection_df.columns.values
                                if cls._INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING[feature] in col
                            ]
                        ]
                        class_inspection_dfs[class_inspection][feature] = class_df

                        class_df_unique = cls._create_df_report(class_df)
                        class_inspection_dfs_unique[class_inspection][feature] = class_df_unique

            elif len(cls._INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING[class_features[0]]) > 1:

                class_df = inspection_df[
                    [
                        col
                        for col in inspection_df.columns.values
                        if any(c in col for c in cls._INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING[class_features[0]])
                    ]
                ]
                class_inspection_dfs[class_inspection] = class_df

                class_df_unique = cls._create_df_report(class_df)
                class_inspection_dfs_unique[class_inspection] = class_df_unique

            else:
                class_df = inspection_df[
                    [
                        col
                        for col in inspection_df.columns.values
                        if cls._INSPECTION_JSON_DF_KEYS_FEATURES_MAPPING[class_features[0]][0] in col
                    ]
                ]
                class_inspection_dfs[class_inspection] = class_df

                class_df_unique = cls._create_df_report(class_df)
                class_inspection_dfs_unique[class_inspection] = class_df_unique

        return class_inspection_dfs, class_inspection_dfs_unique
