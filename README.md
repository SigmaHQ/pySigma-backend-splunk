![Tests](https://github.com/SigmaHQ/pySigma-backend-splunk/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/47c292239759399a6e3c73b0e9656b33/raw/SigmaHQ-pySigma-backend-splunk.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Splunk Backend

This is the Splunk backend for pySigma. It provides the package `sigma.backends.splunk` with the `SplunkBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.splunk`:

* splunk_windows_pipeline: Splunk Windows log support
* splunk_windows_sysmon_acceleration_keywords: Adds fiels name keyword search terms to generated query to accelerate search.

It supports the following output formats:

* default: plain Splunk queries
* savedsearches: Splunk savedsearches.conf format.

## Data model (tstats) query settings

The `data_model` output format generates accelerated `tstats` queries against a Splunk data
model. The following settings let you tune the generated query without changing the Sigma
rules themselves. They are read from the pipeline processing state (set with a
`SetStateTransformation` / the `set_state` pipeline item), so detection logic stays separate
from environment-specific query configuration. Defaults keep the generated query unchanged.

* `summariesonly` (also available as the `summariesonly` backend option, e.g.
  `-O summariesonly=true` with sigma-cli): controls the `tstats summariesonly=...` flag.
  Accepts a boolean or a string (`true`/`false`). When both are set, the pipeline
  processing state takes precedence over the backend option. Default: `false`.

The following are Splunk-specific extensions of the data model output and have no direct
representation in the Sigma standard:

* `tstats_span`: adds `_time` to the `by` clause and a `span=<value>` bucket, e.g.
  `tstats_span: 1h`. The value must match `\d+[a-zA-Z]*`.
* `tstats_aggregations`: a list of additional aggregation functions appended after the
  default `count`. Each entry is a mapping with `func` (one of the supported Splunk stats
  functions, e.g. `values`, `sum`, `dc`), `field`, and an optional `as`/`alias`, e.g.
  `[{func: values, field: Processes.process_name, as: process_names}]`. `count` is always
  present and cannot be redefined here.
* `tstats_aggregation`: a raw aggregation string appended verbatim after `count` (advanced
  use). When set, it takes precedence over `tstats_aggregations`.

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/thomaspatzke/)