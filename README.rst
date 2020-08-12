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

Reports Processing
==================

The reports to be processed can be retrieved in two ways:

- `locally`, providing a path.
- Using `Ceph S3` providing the following environment variables:

   .. code-block:: console

      THOTH_CEPH_KEY_ID=<ceph_key_id>
      THOTH_CEPH_SECRET_KEY=<ceph_key_id>
      THOTH_S3_ENDPOINT_URL=<s3_endpoint_url>
      THOTH_CEPH_HOST=<ceph_host>
      THOTH_CEPH_BUCKET=<ceph_bucket>
      THOTH_CEPH_BUCKET_PREFIX=<ceph_bucket_prefix>
      THOTH_DEPLOYMENT_NAMR=<deployment_name>

see currently available adapters from thoth-storages `here <https://github.com/thoth-station/report-processing/blob/master/thoth/report_processing/enums.py>`__.


Security Indicators
===================

Aggregating Security Indicators using local path:

.. code-block:: python

   from thoth.report_processing.components.security import SecurityIndicatorsBandit, SecurityIndicatorsCloc
   from thoth.report_processing.components.security import SecurityIndicatorsAggregator

   _SI_BANDIT_FOLDER_PATH =<>
   _SI_CLOC_FOLDER_PATH =<>

   security_aggregator = SecurityIndicatorsAggregator()

   si_bandit_report = SecurityIndicatorsBandit.aggregate_security_indicator_bandit_results(
      security_indicator_bandit_repo_path=_SI_BANDIT_FOLDER_PATH, is_local=True
   )[0]

   si_cloc_report = SecurityIndicatorsCloc.aggregate_security_indicator_cloc_results(
      security_indicator_cloc_repo_path=_SI_CLOC_FOLDER_PATH, is_local=True
   )[0]

   aggregated_json = security_aggregator.create_si_aggregated_json(
      si_bandit_report=si_bandit_report, si_cloc_report=si_cloc_report
   )
