import os

from pathlib import Path

from setuptools import find_packages
from setuptools import setup


def get_install_requires():
    with open('requirements.txt', 'r') as requirements_file:
        # TODO: respect hashes in requirements.txt file
        res = requirements_file.readlines()
        return [req.split(' ', maxsplit=1)[0] for req in res if req]


def get_version():
    with open(os.path.join('thoth', 'report_processing', '__init__.py')) as f:
        content = f.readlines()

    for line in content:
        if line.startswith('__version__ ='):
            # dirty, remove trailing and leading chars
            return line.split(' = ')[1][1:-2]
    raise ValueError("No version identifier found")


VERSION = get_version()
setup(
    name='thoth-report-processing',
    version=VERSION,
    description='Code for Thoth experiments in Jupyter notebooks.',
    long_description=Path('README.rst').read_text(),
    long_description_content_type="text/x-rst",
    author='Francesco Murdaca',
    author_email='fmurdaca@redhat.com',
    license='GPLv3+',
    url='https://github.com/thoth-station/report-processing',
    packages=[
        'thoth.{subpackage}'.format(subpackage=p)
        for p in find_packages('thoth/')
    ],
    include_package_data=True,
    install_requires=get_install_requires(),
    zip_safe=False,
    command_options={
        'build_sphinx': {
            'version': ('setup.py', VERSION),
            'release': ('setup.py', VERSION),
        }
    },
)