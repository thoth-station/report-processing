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

"""Security Indicator cloc test suite."""

from .base_test import ReportProcessingTestCase
from thoth.report_processing.components.security import SecurityIndicatorsCloc


class TestSecurityReportsCloc(ReportProcessingTestCase):
    """Test implementation of security indicator cloc."""

    _SI_REPORT_NAME = "security-indicator-54c6daf9"

    _SI_CLOC_FOLDER_PATH = ReportProcessingTestCase.DATA / "security-indicator"

    def test_get_security_indicator_cloc_report(self) -> None:
        """Test retrieving report from local path."""
        si_cloc_reports = SecurityIndicatorsCloc.aggregate_security_indicator_cloc_results(
            security_indicator_cloc_repo_path=self._SI_CLOC_FOLDER_PATH,
            is_local=True,
        )
        assert si_cloc_reports[0]

    def test_get_metadata_df_from_cloc_report(self) -> None:
        """Test obtaining metadata from si cloc report."""
        si_cloc_reports = SecurityIndicatorsCloc.aggregate_security_indicator_cloc_results(
            security_indicator_cloc_repo_path=self._SI_CLOC_FOLDER_PATH,
            is_local=True,
        )
        si_cloc_report = si_cloc_reports[0]
        metadata_retrieved = SecurityIndicatorsCloc()._extract_data_from_si_cloc_metadata(si_cloc_report=si_cloc_report)
        metadata_retrieved_keys = [k for k in metadata_retrieved]
        metadata_test_keys = [
            "datetime_si_cloc",
            "analyzer_si_cloc",
            "analyzer_version_si_cloc",
            "document_id_si_cloc",
            "package_name",
            "package_version",
            "package_index",
        ]
        assert metadata_retrieved_keys == metadata_test_keys
