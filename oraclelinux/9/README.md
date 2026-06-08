# Oracle Linux 9 BFB Build

## ⚠️ Important Configuration Required

Before building, you **must** configure the repository file:

**File:** `oraclelinux/9/repos/rdma-core-63.0-1.0.0-el9-aarch64.repo`
The file has a missing `baseurl` value that should be corrected.

This repository needs to be filled with a URL pointing to a repository that can provide the following OL9 RDMA packages:

The packages should all be of version `63.0-1.0.0` and with an `aarch64` architecture.

- ibacm
- infiniband-diags
- infiniband-diags-compat
- iwpmd
- libibumad
- libibverbs
- libibverbs-unsupported
- libibverbs-unsupported-devel
- libibverbs-utils
- librdmacm
- librdmacm-utils
- python3-pyverbs
- rdma-core
- rdma-core-devel
- srp_daemon

**Action Required:** Edit `oraclelinux/9/repos/rdma-core-63.0-1.0.0-el9-aarch64.repo` and replace `<FILL YOUR BASE URL HERE>` with the actual repository URL that contains these packages.
