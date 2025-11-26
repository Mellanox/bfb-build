# Oracle Linux 8 BFB Build

## ⚠️ Important Configuration Required

Before building, you **must** configure the repository file:

**File:** `oraclelinux/8/repos/rdma-core-56.0-el8-aarch64.repo`

The file has a missing `baseurl` value that should be corrected.

This repository needs to be filled with a URL pointing to a repository that can provide the following OL8 RDMA packages:

The packages should all be of version `56.0-1.0.3` and with an `aarch64` architecture.

- ibacm
- infiniband-diags
- infiniband-diags-compat
- iwpmd
- libibumad
- libibverbs
- libibverbs-utils
- librdmacm
- librdmacm-utils
- python3-pyverbs
- rdma-core
- rdma-core-devel
- srp_daemon

**Action Required:** Edit `oraclelinux/8/repos/rdma-core-56.0-el8-aarch64.repo` and replace `<FILL YOUR BASE URL HERE>` with the actual repository URL that contains these packages.

