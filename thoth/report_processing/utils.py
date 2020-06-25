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

from typing import Optional, Tuple, List, Any
from pathlib import Path
from zipfile import ZipFile

from thoth.storages.si_bandit import SIBanditResultsStore
from thoth.storages.si_cloc import SIClocResultsStore

from thoth.report_processing.exceptions import ThothNotKnownResultStore
from thoth.report_processing.exceptions import ThothMissingDatasetAtPath
from thoth.report_processing.enums import ThothResultStoreEnum


_LOGGER = logging.getLogger(__name__)

STORE = {"si_bandit": SIBanditResultsStore, "si_cloc": SIClocResultsStore}


def extract_zip_file(file_path: Path) -> None:
    """Extract files from zip files.

    :param file_path: Path where the zip file is locally stored.
    """
    with ZipFile(file_path, "r") as zip_file:
        zip_file.printdir()

        _LOGGER.debug("Extracting all files...")
        zip_file.extractall()


def aggregate_thoth_results(
    limit_results: bool = False,
    max_ids: int = 5,
    is_local: bool = True,
    repo_path: Optional[Path] = None,
    store_name: Optional[str] = None,
    is_inspection: Optional[bool] = None,
) -> List[Any]:
    """Aggregate results stored on Ceph or locally from repo for Thoth components reports.

    :param limit_results: reduce the number of reports ids considered to `max_ids`.
    :param max_ids: maximum number of reports ids considered.
    :param is_local: flag to retreive the dataset locally (if not uses Ceph S3 (credentials are required)).
    :param repo_path: required if you want to retrieve the dataset locally and `is_local` is set to True.
    :param store_name: compoent name type (e.g. si_bandit, si_cloc).
    """
    if limit_results:
        _LOGGER.debug(f"Limiting results to {max_ids}!")

    files: List[Any] = []

    if is_local:
        files, counter = _aggregate_thoth_results_from_local(
            repo_path=repo_path, files=files, limit_results=limit_results, max_ids=max_ids
        )

    else:
        files, counter = _aggregate_thoth_results_from_ceph(
            store_name=store_name, files=files, limit_results=limit_results, max_ids=max_ids
        )

    _LOGGER.info("Number of file retrieved is: %r" % counter)

    return files


def _aggregate_thoth_results_from_local(
    files: List[Any], repo_path: Optional[Path] = None, limit_results: bool = False, max_ids: int = 5
) -> Tuple[List[Any], int]:
    """Aggregate Thoth results from local repo."""
    _LOGGER.info(f"Retrieving dataset at path... {repo_path}")
    if not repo_path:
        return files, 0

    if not repo_path.exists():
        raise ThothMissingDatasetAtPath(f"There is no dataset at this path: {repo_path}.")

    counter = 0

    for file_path in repo_path.iterdir():
        _LOGGER.debug(file_path)

        with open(file_path, "r") as json_file_type:
            json_file = json.load(json_file_type)

        files.append(json_file)

        if limit_results:
            if counter == max_ids:
                return files, counter

        counter += 1

    return files, counter


def _aggregate_thoth_results_from_ceph(
    files: List[Any], store_name: Optional[str] = None, limit_results: bool = False, max_ids: int = 5
) -> Tuple[List[Any], int]:
    """Aggregate Thoth results from Ceph."""
    if not store_name:
        return files, 0

    if store_name not in ThothResultStoreEnum.__members__:
        raise ThothNotKnownResultStore(
            f"This store_name {store_name} is not known \
                in Thoth: {ThothResultStoreEnum.__members__.keys()}"
        )

    store_type = STORE[store_name]
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
                return files, counter

        counter += 1

    return files, counter
