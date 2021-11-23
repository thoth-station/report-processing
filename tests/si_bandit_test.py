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

"""Security Indicator bandit test suite."""

from .base_test import ReportProcessingTestCase
from thoth.report_processing.components.security import SecurityIndicatorsBandit


class TestSecurityReportsBandit(ReportProcessingTestCase):
    """Test implementation of security indicator bandit."""

    _SI_REPORT_NAME = "security-indicator-54c6daf9"
    _SI_BANDIT_FOLDER_PATH = ReportProcessingTestCase.DATA / "security-indicator"

    def test_get_security_indicator_bandit_report(self) -> None:
        """Test retrieving report from local path."""
        si_bandit_reports = SecurityIndicatorsBandit.aggregate_security_indicator_bandit_results(
            security_indicator_bandit_repo_path=self._SI_BANDIT_FOLDER_PATH,
            is_local=True,
        )
        assert si_bandit_reports[0]

    def test_get_metadata_df_from_bandit_report(self) -> None:
        """Test obtaining metadata from si bandit report."""
        si_bandit_reports = SecurityIndicatorsBandit.aggregate_security_indicator_bandit_results(
            security_indicator_bandit_repo_path=self._SI_BANDIT_FOLDER_PATH,
            is_local=True,
        )
        si_bandit_report = si_bandit_reports[0]
        si_bandit = SecurityIndicatorsBandit()
        metadata_retrieved = si_bandit._extract_data_from_si_bandit_metadata(si_bandit_report=si_bandit_report)
        metadata_retrieved_keys = [k for k in metadata_retrieved]
        metadata_test_keys = [
            "datetime_si_bandit",
            "analyzer_si_bandit",
            "analyzer_version_si_bandit",
            "document_id_si_bandit",
            "package_name",
            "package_version",
            "package_index",
        ]
        assert metadata_retrieved_keys == metadata_test_keys

    def test_get_severity_confidence_info_from_bandit_report(self) -> None:
        """Test obtaining severity confidence info from si bandit report."""
        si_bandit_reports = SecurityIndicatorsBandit.aggregate_security_indicator_bandit_results(
            security_indicator_bandit_repo_path=self._SI_BANDIT_FOLDER_PATH,
            is_local=True,
        )
        si_bandit_report = si_bandit_reports[0]
        si_bandit = SecurityIndicatorsBandit()
        severity_confidence_info, summary = si_bandit.extract_severity_confidence_info(
            si_bandit_report=si_bandit_report,
        )
        assert not severity_confidence_info

    def test_get_severity_confidence_info_df_from_bandit_report(self) -> None:
        """Test obtaining severity confidence info DataFrame from si bandit report."""
        si_bandit_reports = SecurityIndicatorsBandit.aggregate_security_indicator_bandit_results(
            security_indicator_bandit_repo_path=self._SI_BANDIT_FOLDER_PATH,
            is_local=True,
        )
        si_bandit_report = si_bandit_reports[0]
        si_bandit = SecurityIndicatorsBandit()
        severity_confidence_info_df, summary = si_bandit.create_security_confidence_dataframe(
            si_bandit_report=si_bandit_report,
        )

        severity_confidence_info = severity_confidence_info_df["_total"].to_dict()

        severity_confidence_info_keys = [k for k in severity_confidence_info]
        severity_confidence_info_test_keys = [
            "_total_severity",
        ]
        assert severity_confidence_info_keys == severity_confidence_info_test_keys
