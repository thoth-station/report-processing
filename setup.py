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

"""Setup for thoth-report-processing."""


import os
from pathlib import Path
from setuptools import find_packages
from setuptools import setup


def _get_install_requires():
    with open("requirements.txt", "r") as requirements_file:
        res = requirements_file.readlines()
        return [req.split(" ", maxsplit=1)[0] for req in res if req]


def _get_version():
    with open(os.path.join("thoth", "report_processing", "__init__.py")) as f:
        content = f.readlines()

    for line in content:
        if line.startswith("__version__ ="):
            # dirty, remove trailing and leading chars
            return line.split(" = ")[1][1:-2]
    raise ValueError("No version identifier found")


VERSION = _get_version()
setup(
    name="thoth-report-processing",
    version=VERSION,
    description="Code for processing report from Thoth components.",
    long_description=Path("README.rst").read_text(),
    long_description_content_type="text/x-rst",
    author="Francesco Murdaca",
    author_email="fmurdaca@redhat.com",
    license="GPLv3+",
    url="https://github.com/thoth-station/report-processing",
    download_url="https://pypi.org/project/thoth-report-processing",
    packages=["thoth.{subpackage}".format(subpackage=p) for p in find_packages("thoth/")],
    include_package_data=True,
    install_requires=_get_install_requires(),
    zip_safe=False,
    command_options={"build_sphinx": {"version": ("setup.py", VERSION), "release": ("setup.py", VERSION)}},
)
