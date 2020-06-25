Thoth Report Processing
-----------------------

This library called `thoth-report-processing
<https://pypi.org/project/thoth-report-processing>`__ is used in project `Thoth
<https://thoth-station.ninja>`__ to process all outputs provided by Thoth Components
and stored using `thoth-storages library <https://github.com/thoth-station/storages>`__.

Installation and Usage
======================

The library can be installed via pip or Pipenv from `PyPI
<https://pypi.org/project/thoth-report-processing>`__:

.. code-block:: console

   pipenv install thoth-report-processing

The library does not provide any CLI, it is rather a low level library
supporting other parts of Thoth.

Outputs, Reports Processing
===========================

The outputs, reports can be processed:

- `locally`, providing a path.
- `from Ceph S3`, providing the `store_name`.

from `registered ones <https://github.com/thoth-station/report-processing/blob/master/thoth/report-processing/enums.py>`__
and the following credentials:

   .. code-block:: console

      THOTH_CEPH_KEY_ID=<ceph_key_id>
      THOTH_CEPH_SECRET_KEY=<ceph_key_id>
      THOTH_S3_ENDPOINT_URL=<s3_endpoint_url>
      THOTH_CEPH_HOST=<ceph_host>
      THOTH_CEPH_BUCKET=<ceph_bucket>
      THOTH_CEPH_BUCKET_PREFIX=<ceph_bucket_prefix>
      THOTH_DEPLOYMENT_NAMR=<deployment_name>
