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

"""Security Indicator aggregator test suite."""

import pytest
from tests.base_test import ReportProcessingTestCase

from thoth.report_processing.components.security import SecurityIndicatorsBandit, SecurityIndicatorsCloc
from thoth.report_processing.components.security import SecurityIndicatorsAggregator

from thoth.report_processing.exceptions import ThothSIPackageNotMatchingException


class TestSecurityReportsBandit(ReportProcessingTestCase):
    """Test implementation of security indicator bandit."""

    _SI_BANDIT_REPORTS_PATH = ReportProcessingTestCase.DATA / "security" / "si_bandit"
    _SI_CLOC_REPORTS_PATH = ReportProcessingTestCase.DATA / "security" / "si_cloc"

    def test_create_si_aggreagated_dataframe(self) -> None:
        """Test aggregation of SI analuyzers reports for single package."""
        security_aggregator = SecurityIndicatorsAggregator()

        si_bandit_report = SecurityIndicatorsBandit.aggregate_security_indicator_bandit_results(
            security_indicator_bandit_repo_path=self._SI_BANDIT_REPORTS_PATH
        )[0]

        si_cloc_report = SecurityIndicatorsCloc.aggregate_security_indicator_cloc_results(
            security_indicator_cloc_repo_path=self._SI_CLOC_REPORTS_PATH
        )[0]

        with pytest.raises(ThothSIPackageNotMatchingException):
            assert security_aggregator.create_si_aggregated_dataframe(
                si_bandit_report=si_bandit_report, si_cloc_report=si_cloc_report
            )
