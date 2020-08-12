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

"""Solver test suite."""

from tests.base_test import ReportProcessingTestCase

from thoth.report_processing.components.solver import Solver


class TestSolver(ReportProcessingTestCase):
    """Test implementation of solver results."""

    _SOLVER_FOLDER_PATH = ReportProcessingTestCase.DATA / "solver"

    def test_get_solver_reports(self) -> None:
        """Test retrieving solver results from local path."""
        solver_reports = Solver.aggregate_solver_results(repo_path=self._SOLVER_FOLDER_PATH, is_local=True)
        assert solver_reports

    def test_get_metadata_df_from_solver_report(self) -> None:
        """Test obtaining metadata from si solver report."""
        solver_reports = Solver.aggregate_solver_results(repo_path=self._SOLVER_FOLDER_PATH, is_local=True)
        solver_report = solver_reports["solver-fedora-31-py37-012b745d"]
        metadata_retrieved = Solver.extract_data_from_solver_metadata(solver_report_metadata=solver_report["metadata"])
        metadata_retrieved_keys = [k for k in metadata_retrieved]
        metadata_test_keys = [
            "document_id",
            "datetime",
            "requirements",
            "solver",
            "os_name",
            "os_version",
            "python_interpreter",
            "analyzer_version",
        ]
        assert metadata_retrieved_keys == metadata_test_keys
