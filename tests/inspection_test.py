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

"""Inspection test suite."""

from tests.base_test import ReportProcessingTestCase

from thoth.report_processing.components.inspection import AmunInspection, AmunInspectionsSummary


class TestAdviser(ReportProcessingTestCase):
    """Test implementation of adviser results."""

    _INSPECTIONS_FOLDER_PATH = ReportProcessingTestCase.DATA / "inspections"

    def test_get_inspection_runs(self) -> None:
        """Test retrieving adviser results from local path."""
        inspections_runs = AmunInspection.aggregate_thoth_inspections_results(
            repo_path=self._INSPECTIONS_FOLDER_PATH, is_local=True
        )
        assert inspections_runs

    def test_create_inspection_summary(self) -> None:
        """Test retrieving adviser results from local path."""
        inspections_runs = AmunInspection.aggregate_thoth_inspections_results(
            repo_path=self._INSPECTIONS_FOLDER_PATH, is_local=True
        )

        processed_data = AmunInspection.process_inspection_runs(inspections_runs)
        inspections_df = AmunInspection.create_final_inspection_dataframe(processed_data=processed_data)

        dfs_inspection_classes, dfs_unique_inspection_classes = AmunInspectionsSummary.create_dfs_inspection_classes(
            inspection_df=inspections_df
        )

        assert dfs_unique_inspection_classes
