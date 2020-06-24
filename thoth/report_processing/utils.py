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

"""Utils for report/file processing."""

import logging
import json
import os

from typing import Optional, Union, Tuple
from pathlib import Path
from zipfile import ZipFile

from thoth.storages.result_base import ResultStorageBase
from thoth.storages.adviser import Advi
from thoth.storages.inspections import InspectionResultsStore
from thoth.storages.si_bandit import SIBanditResultsStore
from thoth.storages.si_cloc import SIClocResultsStore
from thoth.storages import SolverResultsStore


_LOGGER = logging.getLogger(__name__)


def extract_zip_file(file_path: Path):
    """Extract files from zip files."""
    with ZipFile(file_path, "r") as zip_file:
        zip_file.printdir()

        _LOGGER.debug("Extracting all the files now...")
        zip_file.extractall()


def aggregate_thoth_results(
    limit_results: bool = False,
    max_ids: int = 5,
    is_local: bool = True,
    repo_path: Optional[Path] = None,
    store_name: Optional[str] = None,
    is_inspection: Optional[str] = None,
) -> Union[list, dict]:
    """Aggregate results stored on Ceph or locally from repo for Thoth components reports.

    :param limit_results: reduce the number of reports ids considered to `max_ids` to test analysis
    :param max_ids: maximum number of reports ids considered
    :param is_local: flag to retreive the dataset locally or from S3 (credentials are required)
    :param repo_path: required if you want to retrieve the dataset locally and `is_local` is set to True
    :param store: ResultStorageBase type depending on Thoth data (e.g solver, performance, adviser, etc.)
    :param is_inspection: flag used only for InspectionResultStore as we store results in batches
    """
    if limit_results:
        _LOGGER.debug(f"Limiting results to {max_ids} to test functions!!")

    if is_inspection:
        files = {}
    else:
        files = []

    if not is_local:
        files, counter = aggregate_thoth_results_from_ceph(
            store_name=store_name, files=files, limit_results=limit_results, max_ids=max_ids
        )

    elif is_local:
        counter = 0

        _LOGGER.debug(f"Retrieving dataset at path... {repo_path}")

        if not repo_path.exists():
            raise Exception("There is no dataset at this path")

        for file_path in repo_path.iterdir():
            _LOGGER.debug(file_path)

            if os.path.isdir(file_path) and is_inspection:
                main_repo = file_path
                files[str(main_repo)] = []

                for file_path in main_repo.iterdir():
                    if "specification" in str(file_path):
                        with open(file_path, "r") as json_file_type:
                            specification = json.load(json_file_type)
                        break

                if specification:
                    for file_path in main_repo.iterdir():
                        if "specification" not in str(file_path):
                            with open(file_path, "r") as json_file_type:
                                json_file = json.load(json_file_type)
                                json_file["requirements"] = specification["python"]["requirements"]
                                json_file["requirements_locked"] = specification["python"]["requirements_locked"]
                                json_file["build_log"] = None

                            json_file["identifier"] = main_repo.stem
                            files[str(main_repo)].append(json_file)

                            if limit_results:
                                if counter == max_ids:
                                    return files

                            counter += 1

            else:

                with open(file_path, "r") as json_file_type:
                    json_file = json.load(json_file_type)

                files.append(json_file)

                if limit_results:
                    if counter == max_ids:
                        return files

                counter += 1

    _LOGGER.info("Number of file retrieved is: %r" % counter)

    return files


def aggregate_thoth_results_from_ceph(
    store_name: str, files: Union[dict, list], limit_results: bool = False, max_ids: int = 5
) -> Tuple[Union[dict, list], int]:
    """Aggregate Thoth results from Ceph."""
    _STORE = {
        "adviser": InspectionResultsStore,
        "inspection": InspectionResultsStore,
        "si-bandit": SIBanditResultsStore,
        "si-cloc": SIClocResultsStore,
        "solver": SolverResultsStore,
    }
    store_type = _STORE[store_name]
    store = store_type()
    store.connect()

    counter = 0

    for document_id in store.get_document_listing():
        _LOGGER.info("Document n. %r", counter + 1)
        _LOGGER.info(document_id)

        report = store.retrieve_document(document_id=document_id)

        files.append(report)

        if limit_results:
            if counter == max_ids:
                return files

        counter += 1

    return files, counter
