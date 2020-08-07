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

"""Enum types used for Thoth components stores."""

from enum import Enum, auto


class ThothSecurityIndicatorsFileStoreEnum(Enum):
    """Class for Thoth SecurityIndicator files enums."""

    bandit = auto()
    cloc = auto()
    aggregated = auto()


class ThothAmunInspectionFileStoreEnum(Enum):
    """Class for Thoth Amun Inspection files enums."""

    specification = auto()
    build_logs = auto()
    job_logs = auto()
    hardware_info = auto()
    results = auto()
