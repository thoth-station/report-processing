# #!/usr/bin/env python3
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

"""Exceptions used within thoth-report-processing package."""


class ThothReportProcessingException(Exception):
    """A base class for thoth-report-processing exception hierarchy."""


class ThothNotKnownResultStore(ThothReportProcessingException):
    """An exception raised when the ResultsStore name is not registered."""


class ThothMissingDatasetAtPath(ThothReportProcessingException):
    """An exception raised when there is no dataset provided at that Path."""


class ThothSecurityIndicatorReportProcessingException(ThothReportProcessingException):
    """Class for thoth-report-processing exception for Security Indicators."""


class ThothSIPackageNotMatchingException(ThothReportProcessingException):
    """An exception raised when trying to aggregate SI reports from different packages."""
