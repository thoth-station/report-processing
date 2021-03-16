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

from thoth.report_processing.components.inspection import AmunInspections, AmunInspectionsSummary


class TestAdviser(ReportProcessingTestCase):
    """Test implementation of adviser results."""

    _INSPECTIONS_FOLDER_PATH = ReportProcessingTestCase.DATA / "inspections"

    def test_get_inspection_runs(self) -> None:
        """Test retrieving adviser results from local path."""
        inspection_runs = AmunInspections.aggregate_thoth_inspections_results(
            repo_path=self._INSPECTIONS_FOLDER_PATH,
            is_local=True,
        )
        assert inspection_runs

    def test_create_inspection_summary(self) -> None:
        """Test retrieving adviser results from local path."""
        inspection_runs = AmunInspections.aggregate_thoth_inspections_results(
            repo_path=self._INSPECTIONS_FOLDER_PATH,
            is_local=True,
        )

        processed_inspection_runs, _ = AmunInspections.process_inspection_runs(inspection_runs)
        inspections_df = AmunInspections.create_inspections_dataframe(
            processed_inspection_runs=processed_inspection_runs,
        )

        results, md_report_complete = AmunInspectionsSummary.produce_summary_report(
            inspections_df=inspections_df,
            is_markdown=True,
        )

        assert md_report_complete

    def test_final_dataframe(self) -> None:
        """Test retrieving adviser results from local path."""
        inspection_runs = AmunInspections.aggregate_thoth_inspections_results(
            repo_path=self._INSPECTIONS_FOLDER_PATH,
            is_local=True,
        )
        processed_inspection_runs, _ = AmunInspections.process_inspection_runs(inspection_runs)

        inspections_df = AmunInspections.create_inspections_dataframe(
            processed_inspection_runs=processed_inspection_runs,
        )

        final_dataframe = AmunInspections.create_final_dataframe(inspections_df=inspections_df)
        assert not final_dataframe.empty

    def test_filter_final_dataframe(self) -> None:
        """Test retrieving adviser results from local path."""
        inspection_runs = AmunInspections.aggregate_thoth_inspections_results(
            repo_path=self._INSPECTIONS_FOLDER_PATH,
            is_local=True,
        )
        processed_inspection_runs, _ = AmunInspections.process_inspection_runs(inspection_runs)

        inspections_df = AmunInspections.create_inspections_dataframe(
            processed_inspection_runs=processed_inspection_runs,
        )

        final_dataframe = AmunInspections.create_final_dataframe(inspections_df=inspections_df)

        filtered_df = AmunInspections.filter_final_inspections_dataframe(
            final_inspections_df=final_dataframe,
            pi_name=["PiMatmul"],
            cpus_number=["2"],
            packages={
                "absl-py": ["absl-py-0.9.0-pypi", "absl-py-0.9.0-pypi"],
                "tensorflow-cpu": ["tensorflow-cpu-2.2.0-pypi"],
            },
        )

        assert not filtered_df.empty
