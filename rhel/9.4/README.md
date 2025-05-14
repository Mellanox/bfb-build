# Notes for RHEL 9.4

## Repositories

### Red Hat Repositories

#### rh.repo
There are several Red Hat repositories that need to be added to the system. 

The `rh.repo` file is a placeholder for the Red Hat repositories. 

Each `base_url` entry in the `rh.repo` file should be replaced with the appropriate Red Hat repository URL.

Same goes for the `gpgkey` entries.

**The BFB image CANNOT be built without the Red Hat repositories.**

Please make sure to edit the `repos/rh.repo` file accordingly before executing the `./bfb-build rhel 9.4` command.