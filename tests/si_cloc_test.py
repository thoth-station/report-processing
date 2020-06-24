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

"""Securit Indicator cloc test suite."""

from .base_test import ReportProcessingTestCase
from thoth.report_processing.components.security import SecurityIndicatorsCloc


class TestSecurityReportsCloc(ReportProcessingTestCase):
    """Test implementation of security indicator cloc."""

    _SI_CLOC_FILE = ReportProcessingTestCase.DATA / "security" / "si_cloc"

    def test_get_security_indicator_cloc_report(self) -> None:
        """Test retrieving report from local path."""
        si_cloc_report = SecurityIndicatorsCloc.aggregate_security_indicator_cloc_results(
            security_indicator_cloc_repo_path=self._SI_CLOC_FILE
        )[0]
        assert si_cloc_report

    def test_get_metadata_df_from_cloc_report(self) -> None:
        """Test obtaining metadata from si cloc report."""
        si_cloc_report = SecurityIndicatorsCloc.aggregate_security_indicator_cloc_results(
            security_indicator_cloc_repo_path=self._SI_CLOC_FILE
        )[0]
        metadata_retrieved = SecurityIndicatorsCloc().extract_data_from_si_cloc_metadata(si_cloc_report=si_cloc_report)
        metadata_retrieved_keys = [k for k in metadata_retrieved]
        metadata_test_keys = [
            "datetime",
            "analyzer",
            "analyzer_version",
            "document_id",
            "package_name",
            "package_version",
            "package_index",
        ]
        assert metadata_retrieved_keys == metadata_test_keys
