```
Overview:
bfb-build project is meant to be used by bluefield customers wishing to build
their own BlueField bootstream (BFB) image for OS deployment on the BlueField
DPUs.

Requirements:
Make sure you have the latest version of docker installed on your server!
To install docker on your x86_64 or aarch64 server please refer to https://docs.docker.com/get-docker/
Note: It is expected that these docker images will run faster on ARM (aarch64) server (without qemu)

In case of using x86_64 server qemu-user-static using will be installed by:
  $ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
  See more info under: https://github.com/multiarch/qemu-user-static

- This step is required to prevent a segmentation fault in QEMU.

```

To build a BlueField boot stream (BFB), run:

```
git clone https://github.com/Mellanox/bfb-build
cd bfb-build
```

For production cards:
````
IMAGE_TYPE=prod ./bfb-build <distro> <version>
````

or for engineering samples (ES)

````
IMAGE_TYPE=dev ./bfb-build <distro> <version>
````

The BFB is created under `/tmp/<distro>/<version>.<pid>` directory.

Set environment variable LEAVE_CONTAINER=yes to leave the docker
container used to build BFB for development/compilation and
customization:

````
LEAVE_CONTAINER=yes IMAGE_TYPE=prod ./bfb-build <distro> <version>
````

# 1. Contents

Common files are located under `<distro>/<version>`:
- bfb-build
- create_bfb
- Dockerfile
- install.sh

## Dockerfile
Contains commands to build a container that will represent the target OS that
runs on BlueField using the following steps:
- Container is created from the base target OS image for ARM64.
- The tools required to be installed on the target OS are added.
- Add repository with DOCA packages that includes kernel for BlueField,
  MLNX_OFED drivers, and other DOCA packages.
- Install doca-runtime, doca-tools and doca-sdk meta-packages that bring and
  install all the packages from the DOCA repository.

## install.sh
This script is run on the BlueField during bfb-install (`cat <BFB> > /dev/rshim0/boot`).
It creates and formats partitions on eMMC device and extracts OS tarball.

## create_bfb
This script is run on the Docker container to turn its file system into the target
BFB.

First, it creates initramfs that are loaded on BlueField during bfb-install
(`cat <BFB> > /dev/rshim0/boot`) and adds all the tools necessary to access eMMC
device on BlueField, creates and formats partitions and extracts the target OS
file system. A tarball file that includes the containers file system and
the install.sh script are also packed into the initramfs.
Then it runs the mlx-mkbfb command to create the BFB file.

The BFB file name is based on the content of `/etc/mlnx-release` file which is
included in bf-release package.

## bfb-build
Runs docker commands to build target OS container and run it to create the BFB.


# 2. Customizations for Target OS Image
## 2.1 User Space Packages and Services
Changes in user space package selection can be done in Dockerfile.

To decrease the BFB size and target OS footprint, consider removing the "doca-devel"
package that brings the development environment required to build DOCA related
software.

To install a smaller subset of the DOCA packages, use the direct list of the
required packages instead of doca-runtime, doca-devel.

The online repository with DOCA packages is available under
https://linux.mellanox.com/public/repo/doca/latest.

## 2.2 Kernel changes
To install a customized kernel on the BlueField OS, it is required to rebuild
MLNX_OFED driver packages and other BlueField SoC drivers.

The relevant source packages are available under
https://linux.mellanox.com/public/repo/bluefield/latest/extras/.

### Ubuntu 24.04: built-in custom kernel support

`ubuntu/24.04` can do this for you. Put your kernel `.deb` packages in a
directory and set `CUSTOM_KERNEL=yes`:

````
CUSTOM_KERNEL=yes \
CUSTOM_KERNEL_DEBS=/path/to/my-kernel-debs \
./bfb-build ubuntu 24.04
````

The directory must contain at least `linux-image-*`, `linux-modules-*` and the
matching `linux-headers-*` packages. The headers are required: MLNX_OFED is
compiled against `/lib/modules/<kernel>/build`.

What this changes compared to a default build:

- the NVIDIA BlueField kernel pinned in `ubuntu/24.04/kernel-packages` is not
  installed; your packages are installed instead
- `doca-runtime-user` / `doca-devel-user` are installed instead of
  `doca-runtime` / `doca-devel`. These pull the complete DOCA user space but
  none of the prebuilt, kernel-version-pinned DOCA kernel modules
  (`doca-runtime = doca-runtime-kernel + doca-runtime-user`)
- MLNX_OFED is rebuilt from source against your kernel and installed, before
  `create_bfb` packs the root filesystem

BlueField SoC drivers (`mlxbf-tmfifo`, `mlxbf-gige`, `gpio-mlxbf*`, `i2c-mlxbf`,
`mlxbf-pmc`, `pinctrl-mlxbf3`, `pwr-mlxbf`, `sdhci-of-dwcmshc`, ...) are **not**
rebuilt. On Ubuntu 22.04 and 24.04 they are part of the kernel itself, so a
kernel derived from the BlueField kernel source already contains them. This is
the main difference from the RPM based flow described below.

Additional variables:

| Variable | Default | Purpose |
|---|---|---|
| `CUSTOM_KERNEL` | `no` | set to `yes` to enable the custom kernel flow |
| `CUSTOM_KERNEL_DEBS` | - | directory holding the kernel `.deb` files |
| `CUSTOM_KERNEL_VERSION` | auto-detect | kernel release string, e.g. `6.8.0-1022-bluefield`. Set it when more than one kernel ends up installed |
| `MLNX_OFED_SRC_URL` | `<BASE_URL>/doca/<DOCA_VERSION>/SOURCES/mlnx_ofed/MLNX_OFED_SRC-debian-<ver>.tgz` | MLNX_OFED debian sources |
| `MLNX_OFED_SRC_LOCAL` | - | use an already-downloaded tarball instead of fetching it |
| `OFED_KERNEL_EXTRA_ARGS` | BlueField DPU flag set | passed to the MLNX_OFED kernel configure script |
| `OFED_INSTALL_EXTRA_ARGS` | - | extra `install.pl` flags, e.g. `--without-depcheck` |

MLNX_OFED sources are published per DOCA release under
`https://linux.mellanox.com/public/repo/doca/<doca-version>/SOURCES/mlnx_ofed/`,
alongside the BlueField SoC driver sources in `../SoC/`. The MLNX_OFED version
is paired with the DOCA release, so `MLNX_OFED_VERSION` in `bfb-build` must
match what is published for `DOCA_VERSION` (DOCA 3.4.0 pairs with MLNX_OFED
26.04-0.8.5.0, DOCA 3.4.1 with 26.04-1.1.0.0). If the download fails, check
that pairing first, or supply a local copy with `MLNX_OFED_SRC_LOCAL`.

The resulting image and container are suffixed with `_custom_kernel`, so a
custom kernel build does not overwrite a default one.

The two modes are generated from a single `ubuntu/24.04/Dockerfile.j2` template.
The committed `ubuntu/24.04/Dockerfile` is the default-mode rendering of that
template, so default builds work unchanged and do not require Jinja2. Rendering
the custom kernel variant requires `python3-jinja2`.

**Example for RPM based Distros:**
The following steps can be added to the Dockerfile based on the real kernel and
MLNX_OFED versions.

After installing the customized kernel and kernel-devel packages, download and
build MLNX_OFED drivers:

````
wget https://linux.mellanox.com/public/repo/bluefield/latest/extras/mlnx_ofed/MLNX_OFED_SRC-25.04-0.6.0.0.tgz
tar xzf MLNX_OFED_SRC-25.04-0.6.0.0.tgz
cd MLNX_OFED_SRC-25.04-0.6.0.0
./install.pl -k <kernel version> --kernel-sources /lib/modules/<kernel version>/build \
	--kernel-extra-args '--with-sf-cfg-drv --without-xdp' \
	--kernel-only --build-only
cd ..
````

Binary RPMS can be found under `MLNX_OFED_SRC-25.04-0.6.0.0/RPMS` directory.
````
find MLNX_OFED_SRC-25.04-0.6.0.0/RPMS -name '*rpm' -a ! -name '*debuginfo*rpm' -exec rpm -ihv '{}' \;
````

**Build and install BlueField SoC drivers:**

````
cd /tmp && wget -r -np -nH --cut-dirs=3 -R "index.html*" https://linux.mellanox.com/public/repo/bluefield/<BLUEFIELD_VERSION>/extras/SRPMS/
mkdir -p /tmp/<BLUEFIELD_VERSION>/extras/{SPECS,RPMS,SOURCES,BUILD}
for p in <BLUEFIELD_VERSION>/extras/SRPMS/*.src.rpm; do rpmbuild --rebuild -D "debug_package %{nil}" -D "KVERSION <kernel version>" --define "_topdir /tmp/<BLUEFIELD_VERSION>/extras" $p;done
rpm -ivh --force /tmp/<BLUEFIELD_VERSION>/extras/RPMS/aarch64/*.rpm

E.g:

cd /tmp && wget -r -np -nH --cut-dirs=3 -R "index.html*" https://linux.mellanox.com/public/repo/bluefield/4.11.0-13611/extras/SRPMS/
mkdir -p /tmp/4.11.0-13611/extras/{SPECS,RPMS,SOURCES,BUILD}
for p in 4.11.0-13611/extras/SRPMS/*.src.rpm; do rpmbuild --rebuild -D "debug_package %{nil}" -D "KVERSION <kernel version>" --define "_topdir /tmp/4.11.0-13611/extras" $p;done
rpm -ivh --force /tmp/4.11.0-13611/extras/RPMS/aarch64/*.rpm
````

After installing MLNX_OFED drivers and BlueField SoC drivers, install DOCA user
space packages individually:

**DOCA runtime packages:**

````
yum install -y doca-runtime-user
````

**DOCA SDK packages:**

````
yum install -y doca-devel-user
````

Update the kernel version parameter for the `create_bfb` command at the end of the
Dockerfile like so:

````
ex /root/workspace/create_bfb -k <kernel>
````

To change the resulted BFB name and version edit `/etc/mlnx-release` file after
bf-release RPM installation.

**See the example of BCLinux under:**

https://github.com/Mellanox/bfb-build/blob/master/bclinux/7.6/Dockerfile

https://github.com/Mellanox/bfb-build/blob/master/bclinux/7.6/build_bclinux_bfb

## 2.3 Customization of the BFB installation environment
As mentioned above, create_bfb creates the target BFB file.
BFB includes a dump-initramfs-v0 file that represents a small Linux image that is
loaded on DPU during the BFB installation. To add more tools or whole packages
to this initramfs image, edit the corresponding Dockerfile and add the relevant
lines below:

**Add wget utility to the initramfs**
```
ENV ADDON_TOOLS="wget"
```

**Add mlnx-tools RPM to the initramgs (RPM based Distros)**
```
ENV ADDON_RPMS="mlnx-tools"
```

**Add mlnx-tools DEB to the initramgs (DEB based Distros)**
```
ENV ADDON_DEBS="mlnx-tools"
```

# 3. Building your own OS Image
bfb-build environment use [APT/YUM repositories](https://linux.mellanox.com/public/repo/doca/) with DOCA binary packages built
for the specific OS.
If the required OS is binary compatible with one of the supported OS that have
prebuilt DOCA binaries then BFB can be created based on existing packages.
Use the Dockerfile for the compatible OS.<br />
E.g.:<br />
For OS binary compatible with RHEL8.6:<br />
Use [rockylinux/8.6/Dockerfile](https://github.com/Mellanox/bfb-build/blob/master/rockylinux/8.6/Dockerfile) as a
template and change the base container in the Dockerfile to use the required OS:<br />
[from --platform=linux/arm64 rockylinux:8.6.20227707](https://github.com/Mellanox/bfb-build/blob/master/rockylinux/8.6/Dockerfile#L1)<br />
For the kernel part refer to the [Kernel changes](https://github.com/Mellanox/bfb-build#22-kernel-changes) section above.


**Notes:**
```
This environment was tested on:
- Ubuntu 20.04.5 x86_64 with Docker version 20.10.12
- RHEL 7.6 aarch64 with Docker version 20.10.17, build 100c701
```

**Known issues:**
```
To build Ubuntu 22.04 BFB on CentOS host Docker >= 20.10.9 is required.
For more details see:
https://askubuntu.com/questions/1408090/cannot-run-apt-update-on-ubuntu-22-docker-image-on-a-centos-host
```

```
bfb-build fails due to qemu issue:
  Error:
  qemu: uncaught target signal 11 (Segmentation fault) - core dumped
  Segmentation fault (core dumped)

  As a workaround to the issues above install qemu-user-static package using:
  $ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
  See more info under: https://github.com/multiarch/qemu-user-static
```

**Additional information**

NVIDIA BLUEFIELD DPU PLATFORM OPERATING SYSTEM DOCUMENTATION: https://docs.nvidia.com/networking/display/BlueFieldDPUOSLatest
