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

"""Thoth components classes to process outputs."""

from .adviser import Adviser
from .inspection import AmunInspections
from .inspection import AmunInspectionsSummary
from .inspection import AmunInspectionsStatistics
from .security import SecurityIndicatorsBandit
from .security import SecurityIndicatorsCloc
from .security import SecurityIndicatorsAggregator
from .solver import Solver

__all__ = [
    "Adviser",
    "AmunInspections",
    "AmunInspectionsStatistics",
    "AmunInspectionsSummary",
    "SecurityIndicatorsBandit",
    "SecurityIndicatorsCloc",
    "SecurityIndicatorsAggregator",
    "Solver",
]
