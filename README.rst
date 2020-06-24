Thoth Report Processing
-----------------------

This library provides a library called `thoth-report-processing
<https://pypi.org/project/thoth-report-processing>`__ used in project `Thoth
<https://thoth-station.ninja>`__.
The library contains methods to process all outputs provided by Thoth Components.

Installation and Usage
======================

The library can be installed via pip or Pipenv from `PyPI
<https://pypi.org/project/thoth-report-processing>`__:

.. code-block:: console

   pipenv install thoth-report-processing

The library does not provide any CLI, it is rather a low level library
supporting other parts of Thoth.

You can run prepared test-suite via the following command:

.. code-block:: console

  pipenv install --dev
  pipenv run python3 setup.py test
