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

"""Solver reports processing methods."""

import logging
import os
import json

from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from thoth.report_processing.exceptions import ThothMissingDatasetAtPath

from thoth.storages.solvers import SolverResultsStore

# set up logging
DEBUG_LEVEL = bool(int(os.getenv("DEBUG_LEVEL", 0)))

if DEBUG_LEVEL:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

_LOGGER = logging.getLogger(__name__)


class Solver:
    """Class of methods used to process results from Solver."""

    @classmethod
    def aggregate_solver_results(
        cls,
        limit_results: bool = False,
        max_ids: int = 5,
        is_local: bool = False,
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

        if not is_local:
            files, counter = cls._aggregate_thoth_results_from_ceph(
                files=files,
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
        store_files: Optional[List[str]] = None,
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

            if "solver" not in file_path.name:
                raise Exception(f"This repo is not part of solver! {repo_path}")

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
        store_files: Optional[List[str]] = None,
        limit_results: bool = False,
        max_ids: int = 5,
    ) -> Tuple[Dict[str, Any], int]:
        """Aggregate Thoth results from Ceph."""
        solver_store = SolverResultsStore()
        solver_store.connect()

        solver_ids = list(solver_store.get_document_listing())

        _LOGGER.info("Number of Solver reports identified is: %r" % len(solver_ids))

        number_solver_results = len(solver_ids)

        counter = 0

        if limit_results:
            _LOGGER.debug(f"Limiting results to {max_ids} to test functions!!")

        for n, document_id in enumerate(solver_ids):
            _LOGGER.debug(f"Analysis {document_id} n.{counter + 1}/{number_solver_results}")

            try:
                document = solver_store.retrieve_document(document_id)
                files[document_id] = document

                counter += 1

                _LOGGER.info("Documents retrieved: %r", counter)

                if limit_results:
                    if counter == max_ids:
                        return files, counter

            except Exception as exception:
                _LOGGER.exception(f"Exception during retrieval of solver result {document_id}: {exception}")
                continue

        return files, counter

    @staticmethod
    def construct_solver_from_metadata(solver_report_metadata: Dict[str, Any]) -> str:
        """Construct solver from solver report metadata."""
        os_name = solver_report_metadata["os_release"]["name"].lower()
        os_version = "".join(
            [
                release_version
                for release_version in solver_report_metadata["os_release"]["version"]
                if release_version.isdigit()
            ],
        )
        python_interpreter = f'{solver_report_metadata["python"]["major"]}{solver_report_metadata["python"]["minor"]}'
        solver = f"{os_name}-{os_version}-py{python_interpreter}"

        return solver

    @classmethod
    def extract_data_from_solver_metadata(cls, solver_report_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data from solver report metadata."""
        solver = cls.construct_solver_from_metadata(solver_report_metadata)
        solver_parts = solver.split("-")

        requirements = solver_report_metadata["arguments"]["python"]["requirements"]

        extracted_metadata = {
            "document_id": solver_report_metadata["document_id"],
            "datetime": solver_report_metadata["datetime"],
            "requirements": requirements,
            "solver": solver,
            "os_name": solver_parts[0],
            "os_version": solver_parts[1],
            "python_interpreter": ".".join(solver_parts[2][2:]),
            "analyzer_version": solver_report_metadata["analyzer_version"],
        }

        return extracted_metadata

    @staticmethod
    def extract_tree_from_solver_result(solver_report_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract data from solver report result."""
        packages = []
        for python_package_info in solver_report_result["tree"]:
            package = {
                "package_name": python_package_info["package_name"],
                "package_version": python_package_info["package_version_requested"],
                "index_url": python_package_info["index_url"],
                "importlib_metadata": python_package_info["importlib_metadata"]["metadata"],
                "dependencies": python_package_info["dependencies"],
            }
            packages.append(package)

        return packages

    @staticmethod
    def extract_errors_from_solver_result(solver_report_result_errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract all errors from solver report (if any)."""
        errors = []
        for error in solver_report_result_errors:
            errors.append(
                {
                    "package_name": error["package_name"],
                    "package_version": error["package_version"],
                    "index_url": error["index_url"],
                    "type": error["type"],
                    "command": error["details"]["command"] if "command" in error["details"] else None,
                    "message": error["details"]["message"] if "message" in error["details"] else None,
                    "return_code": error["details"]["return_code"] if "return_code" in error["details"] else None,
                    "stderr": error["details"]["stderr"] if "stderr" in error["details"] else None,
                    "stdout": error["details"]["stdout"] if "stdout" in error["details"] else None,
                    "timeout": error["details"]["timeout"] if "timeout" in error["details"] else None,
                },
            )
        return errors
