#!/usr/bin/env python3
# ex:ts=4:sw=4:sts=4:et
# -*- tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*-
#
# Copyright (c) 2020 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.
#
# Author: Vladimir Sokolovsky <vlad@mellanox.com>
#

import sys
import os
import stat
import shutil
import argparse
import glob
import re
import subprocess
import datetime
import json
import csv
from pprint import pprint

__author__ = "Vladimir Sokolovsky <vlad@mellanox.com>"
__version__ = "1.0"

wdir = os.path.dirname(os.path.realpath(__file__))
manifests_dir = wdir + os.sep + "manifests"
os.environ['DEBIAN_FRONTEND'] = 'noninteractive'

AllPackages = {}
debug_enabled = False
run_quiet = 0
RSYNC_PASSWORD = '3tango11'
distro = ""
kernel = ""
skip_type_kernel = False
MAX_GET_RETRIES = 1

is_debian = 0
if os.path.exists("/etc/debian_version"):
    is_debian = 1

DISTRO_REQUIRED_PACKAGES = ["wget"]
if is_debian:
    DISTRO_REQUIRED_PACKAGES += ["rpm2cpio", "rpm"]

DISTRO_PACKAGES2REMOVE = []
if is_debian:
    DISTRO_PACKAGES2REMOVE = ["rpm2cpio", "rpm"]

DEB_FIX_BROKEN = "env FLASH_KERNEL_SKIP=yes DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y || true"

helptext                = """
usage: packages.py [OPTION]

  -h, --help
  -d, --debug       Turn on verbose messages and command confirmation.

"""

#
# Utilities
#
def fatal(msg):
    print (sys.stderr, 'FATAL: ' + str(datetime.datetime.now()) + ': ' + msg)

def warn(msg):
    print (sys.stderr, 'WARNING: ' + str(datetime.datetime.now()) + ': ' + msg)

def info(msg):
    if not run_quiet:
        print (sys.stderr, 'INFO: ' + str(datetime.datetime.now()) + ': ' + msg)

def debug(msg):
    if debug_enabled:
        print (sys.stderr, 'DEBUG: ' + str(datetime.datetime.now()) + ': ' + msg)


def get_status_output(cmd, print_in_fail=True):
    rc, output = (0, '')
    try:
        debug(cmd)
        output_bytes = subprocess.check_output(cmd, encoding='utf-8', stderr=subprocess.STDOUT,
                                         shell=True, universal_newlines=True)
        output = str(output_bytes)
    except subprocess.CalledProcessError as e:
        rc, output = (e.returncode, e.output)
    if rc and print_in_fail:
        print('Running %s fail%s(error[%d], output: %s)' %
              (cmd, os.linesep, rc, output))
    return rc, output


def get_rpm_version(rpm):
    if not os.path.exists(rpm):
        fatal("File {r} does not exist".format(r=rpm))
        sys.exit(1)

    cmd = "rpm -qp --queryformat '[%{f}]' {r} ".format(f="{VERSION}", r=rpm)
    rc, output = get_status_output(cmd, print_in_fail=False)
    return output.strip()

def get_rpm_source(rpm):
    if not os.path.exists(rpm):
        fatal("File {r} does not exist".format(r=rpm))
        sys.exit(1)

    cmd = "rpm -qp --queryformat '[%{f}]' {r} ".format(f="{SOURCE}", r=rpm)
    rc, output = get_status_output(cmd, print_in_fail=False)
    return output.strip()
    
def is_installed(name):
    if is_debian:
        cmd = "/usr/bin/dpkg-query -l {n} 2> /dev/null | awk '/^[rhi][iU]/{f}'".format(f="{print $2}", n=name)
    else:
        cmd = "rpm -q --queryformat '[%{f}]' {n} ".format(f="{NAME}", n=name)

    rc, output = get_status_output(cmd, print_in_fail=False)

    return output.strip().split(':')[0] == name


def get_distro():
    if not os.path.exists("/etc/os-release"):
        fatal("Failed to get release OS version")
        sys.exit(1)

    version_id = ""
    os_id = ""
    with open("/etc/os-release") as os_rel:
        for line in os_rel:
            if line.startswith("VERSION_ID="):
                version_id = line.replace('"','').split('=')[1]
            elif line.startswith("ID="):
                os_id = line.replace('"','').split('=')[1]
    if os_id == 'ol':
        os_id = "centos"
        version_id = "8"
    return "{os_id}{version_id}".format(os_id=os_id.strip(), version_id=version_id.strip())


def install_distro_package(name):
    if is_debian:
        cmd = "env FLASH_KERNEL_SKIP=yes apt install -y {n} || true; {fix_broken}".format(n=name, fix_broken=DEB_FIX_BROKEN)
    else:
        if any([ rpmdistro in distro for rpmdistro in ['centos8','rocky','openEuler','ol8.7'] ]):
            cmd = "yum install -y {}".format(name)
        else:
            cmd = "yum install -y --enablerepo=updates --enablerepo=extras {}".format(name)

    rc, output = get_status_output(cmd, print_in_fail=True)
    return rc


def remove_distro_package(name):
    if is_debian:
        cmd = "env FLASH_KERNEL_SKIP=yes apt remove --purge -y {}".format(name)
    else:
        cmd = "yum remove -y {}".format(name)

    rc, output = get_status_output(cmd, print_in_fail=True)
    if rc:
        sys.exit(rc)


def get_value(conf, key):
    if key in conf:
        if isinstance(conf[key], dict) and key in ["os_build_dep", "os_run_dep", "pre_build", "build_cmd", "custom_version_cmd", "internal_build_dep", "internal_run_dep", "install_cmd", "pre_install", "post_install"]:
            for sub_key in conf[key].keys():
                if sub_key in distro:
                    return conf[key][sub_key]
        else:
            return conf[key]

    if key in ["available_condition"]:
        return None

    if key in ["skip_condition"]:
        return None

    return {}


def get_extract_command(tarball):
    if tarball.endswith('tar.gz') or tarball.endswith('tgz'):
        return 'tar -xzf'
    elif tarball.endswith('bz2'):
        return 'tar -xjf'
    elif tarball.endswith('xz'):
        return 'tar -xJf'
    else:
        return 'tar -xzf'


class Package:
    def __init__(self, name, conf):
        self.name = get_value(conf, 'name') or name
        self.is_installed = 0
        self.getMethod = get_value(conf, 'getMethod')
        if self.getMethod == "git":
            self.git_url = get_value(conf, 'git_url')
            self.git_branch = get_value(conf, 'git_branch')
        elif self.getMethod == "file":
            self.file = get_value(conf, 'file')
        self.bin = None
        self.get_cmd = get_value(conf, 'get_cmd')
        self.extract_cmd = get_value(conf, 'extract_cmd')
        self.version = get_value(conf, 'version')
        self.post_clone_cmd = get_value(conf, 'post_clone_cmd')
        self.pre_configure = get_value(conf, 'pre_configure') or ":"
        self.rpm_spec = get_value(conf, 'rpm_spec')
        self.rpm_tar_ext = get_value(conf, 'rpm_tar_ext') or 'tar.gz'
        self.os_build_dep = get_value(conf, 'os_build_dep')
        self.os_run_dep = get_value(conf, 'os_run_dep')
        self.internal_build_dep = get_value(conf, 'internal_build_dep')
        self.internal_run_dep = get_value(conf, 'internal_run_dep')

        self.env = get_value(conf, 'env')
        self.type = get_value(conf, 'type') or "user"
        self.custom_version_cmd = get_value(conf, 'custom_version_cmd')
        self.pre_build = get_value(conf, 'pre_build')
        self.post_build = get_value(conf, 'post_build')
        self.pre_install = get_value(conf, 'pre_install')
        self.post_install = get_value(conf, 'post_install')
        self.build_cmd = get_value(conf, 'build_cmd')
        self.install_cmd = get_value(conf, 'install_cmd')
        self.available_condition = get_value(conf, 'available_condition')
        self.skip_condition = get_value(conf, 'skip_condition')
        self.version = None
        self.log_name = name + ".log"
        self.logfd = open("{w}/{f}".format(w=wdir, f=self.log_name), "a")
        self.src_rpm = None
        self.tarball = None
        self.source = None

    def log(self, msg):
        sys.stdout.buffer.write(msg.encode('utf-8'))
        self.logfd.buffer.write(msg.encode('utf-8'))

    def close_log(self):
        self.logfd.close()

    def skip_package(self):
        debug(f"Package: {self.name} Skip condition: {self.skip_condition}")
        if self.skip_condition is None:
            return False

        for key in self.skip_condition.keys():
            if key == "kernel":
                if kernel in self.skip_condition["distro"]:
                    return True
            if key == "distro":
                if distro in self.skip_condition["distro"]:
                    return True

        print("Package {} should not be skipped.".format(self.name))
        return False

    def is_available(self):
        debug(f"Package: {self.name} Available condition: {self.available_condition}")
        if self.available_condition is None:
            return True

        for key in self.available_condition.keys():
            if key == "kernel":
                if kernel in self.available_condition["kernel"]:
                    return True
            if key == "distro":
                if distro in self.available_condition["distro"]:
                    return True

        print("Package {} is not available.".format(self.name))
        return False

    def get_package(self):
        shutil.rmtree("{w}/{n}".format(w=wdir, n=self.name), ignore_errors=True)
        os.mkdir("{w}/{n}".format(w=wdir, n=self.name))
        if self.getMethod == "git":
            cmd = "git clone -s --bare {url} {w}/{n}/src/.git; \
                    cd {w}/{n}/src; \
                    git config core.bare false; \
                    git config core.logallrefupdates true; \
                    git checkout {ref}; \
                    {pre_configure}; \
                    test -x ./autogen.sh && ./autogen.sh || true; \
                    test -x ./configure && ./configure || true; \
                    ".format(url=self.git_url, w=wdir, n=self.name, ref=self.git_branch, pre_configure=self.pre_configure)
            rc, output = get_status_output(cmd)
            self.log(f"{cmd}\n{output}")
            if rc:
                fatal("Failed to clone {}\n{cmd}\n{output}\nExit status: {rc}".format(self.git_url, cmd=cmd, output=output, rc=rc))
                return rc

            if self.post_clone_cmd:
                cmd = "cd {w}/{n}/src; {c}".format(w=wdir, n=self.name, c=self.post_clone_cmd)
                rc, output = get_status_output(cmd)
                self.log(f"{cmd}\n{output}")
                if rc:
                        fatal("Failed to run post_clone_cmd {}\n{cmd}\n{output}\nExit status: {rc}".format(self.git_url, cmd=cmd, output=output, rc=rc))
                        return rc

            if self.custom_version_cmd:
                cmd = "cd {w}/{n}/src; {c}".format(w=wdir, n=self.name, c=self.custom_version_cmd)
            else:
                if is_debian:
                    cmd = "cd {w}/{n}/src; dpkg-parsechangelog --show-field Version 2> /dev/null | cut -d \- -f 1".format(w=wdir, n=self.name)
                else:
                    if self.rpm_spec:
                        cmd = "cd {w}/{n}/src; find . -name \"*.spec\" | grep -v {spec} | xargs git rm -f; git config user.email 'vlad@nvidia.com'; git commit -a -m'Removed extra RPM spec files'".format(w=wdir, n=self.name, f="{VERSION}", spec=self.rpm_spec)
                        rc, output = get_status_output(cmd)
                        self.log(f"{cmd}\n{output}")
                        cmd = "rpm -q --qf '[%{f}]\\n' --specfile {w}/{n}/src/{spec} 2> /dev/null | head -1".format(w=wdir, n=self.name, f="{VERSION}", spec=self.rpm_spec)
                    else:
                        cmd = "find {w}/{n}/src -name \"*.spec\" -exec rpm -q --qf '[%{f}]\\n' --specfile '{spec}' 2> /dev/null \;| head -1".format(w=wdir, n=self.name, f="{VERSION}", spec="{}")
            rc, output = get_status_output(cmd)
            self.log(f"{cmd}\n{output}")
            if rc:
                fatal("Failed to get package version.\nCmd: {cmd}\n{output}\nExit status: {rc}".format(cmd=cmd, output=output, rc=rc))
                return rc
            self.version = output.strip()
            debug ("Name={n} Version={v}".format(n=self.name, v=self.version))
            if not is_debian:
                cmd = "cd {w}/{n}/; cp -a src {n}-{v}; /bin/rm -rf {n}-{v}/.git; \
                        mkdir SOURCES SPECS; \
                        find {w}/{n}/{n}-{v} -name \"*.spec\" -exec cp '{spec}' {w}/{n}/SPECS/ \;; \
                        tar czf {w}/{n}/SOURCES/{n}-{v}.{z} {n}-{v}; \
                        rpmbuild -bs --define \"_topdir {w}/{n}\" --define \"_srcrpmdir {w}/{n}/src\" --define \"_dist %{nil}\" --define \"dist %{nil}\" {w}/{n}/SPECS/*.spec \
                        ".format(w=wdir, n=self.name, v=self.version, nil="{nil}", z=self.rpm_tar_ext, spec="{}")
                rc, output = get_status_output(cmd)
                self.log(f"{cmd}\n{output}")
                if rc:
                    fatal("Failed to build source RPM.\nCmd: {cmd}\n{output}\nExit status: {rc}".format(cmd=cmd, output=output, rc=rc))
                    return rc
                self.src_rpm = glob.glob("{w}/{n}/src/*.src.rpm".format(w=wdir, n=self.name))[0].split(os.sep)[-1]

        elif self.getMethod == "file":
            if self.get_cmd:
                cmd = "cd {w}/{n}; export distro={distro}; {get_cmd}".format(w=wdir, n=self.name, get_cmd=self.get_cmd, distro=distro)
            else:
                cmd = "cd {w}/{n}; wget --no-verbose {f}".format(f=self.file, w=wdir, n=self.name)
            rc, output = get_status_output(cmd)
            self.log(f"{cmd}\n{output}")
            if rc:
                fatal("Failed to get {}\n{output}\nExit status: {rc}".format(self.file, output=output, rc=rc))
                return rc

            if "src.rpm" in self.file:
                self.src_rpm = glob.glob("{w}/{n}/*.src.rpm".format(w=wdir, n=self.name))[0].split(os.sep)[-1]
                self.version = get_rpm_version("{w}/{n}/{s}".format(w=wdir, n=self.name, s=self.src_rpm))
                self.source = get_rpm_source("{w}/{n}/{s}".format(w=wdir, n=self.name, s=self.src_rpm))
                if is_debian:
                    cmd = "cd {w}/{n}; rpm2cpio {f} | cpio -id; {extract} {s}".format(f=self.src_rpm, w=wdir, n=self.name, extract=get_extract_command(self.source), s=self.source)
                    rc, output = get_status_output(cmd)
                    self.log(f"{cmd}\n{output}")
                    if rc:
                        fatal("Failed to extract from source RPM {}\n{output}\nExit status: {rc}".format(self.src_rpm, output=output, rc=rc))
                        return rc
                    shutil.move("{w}/{n}/{n}-{v}".format(w=wdir, n=self.name, v=self.version), "{w}/{n}/src".format(w=wdir, n=self.name))
                else:
                    cmd = "mkdir -p {w}/{n}/src; mv {w}/{n}/{s} {w}/{n}/src".format(w=wdir, n=self.name, s=self.src_rpm)
                    rc, output = get_status_output(cmd)
                    self.log(f"{cmd}\n{output}")
                    if rc:
                        fatal("Failed to move source RPM {}\n{output}\nExit status: {rc}".format(self.src_rpm, output=output, rc=rc))
                        return rc
            elif "deb" in self.file:
                self.bin = glob.glob("{w}/{n}/*.deb".format(w=wdir, n=self.name))[0].split(os.sep)[-1]
                cmd = "cd {w}/{n}/; dpkg-deb -f {d} Version".format(w=wdir, n=self.name, d=self.bin)
                rc, output = get_status_output(cmd)
                self.version = output.strip()
            elif "rpm" in self.file:
                self.bin = glob.glob("{w}/{n}/*.rpm".format(w=wdir, n=self.name))[0].split(os.sep)[-1]
                self.version = get_rpm_version("{w}/{n}/{b}".format(w=wdir, n=self.name, b=self.bin))
            if "tar.gz" in self.file:
                self.tarball = glob.glob("{w}/{n}/{n}*.*z".format(w=wdir, n=self.name))[0].split(os.sep)[-1]
                if self.extract_cmd:
                    cmd = "cd {w}/{n}; {c}".format(w=wdir, n=self.name, c=self.extract_cmd)
                    rc, output = get_status_output(cmd)
                    self.log(f"{cmd}\n{output}")
                    if rc:
                            fatal("Failed to run extract_cmd {}\n{cmd}\n{output}\nExit status: {rc}".format(self.git_url, cmd=cmd, output=output, rc=rc))
                            return rc
                else:
                    if is_debian:
                        cmd = "cd {w}/{n}; {extract} {t}".format(w=wdir, n=self.name, extract=get_extract_command(self.tarball), t=self.tarball)
                        rc, output = get_status_output(cmd)
                        self.log(f"{cmd}\n{output}")
                        if rc:
                            fatal("Failed to extract from tarball {}\n{output}\nExit status: {rc}".format(self.tarball, output=output, rc=rc))
                            return rc
                        cmd = "cd {w}/{n}/{n}*; dpkg-parsechangelog --show-field Version | cut -d \- -f 1".format(w=wdir, n=self.name)
                        rc, output = get_status_output(cmd)
                        self.log(f"{cmd}\n{output}")
                        if rc:
                            fatal("Failed to get package version.\nCmd: {cmd}\n{output}\nExit status: {rc}".format(cmd=cmd, output=output, rc=rc))
                            return rc
                        self.version = output.strip()
                        shutil.move("{w}/{n}/{n}-{v}".format(w=wdir, n=self.name, v=self.version), "{w}/{n}/src".format(w=wdir, n=self.name))
                    else:
                        cmd = "mkdir -p {w}/{n}/src; \
                                mv {w}/{n}/{t} {w}/{n}/src".format(w=wdir, n=self.name, t=self.tarball)
                        rc, output = get_status_output(cmd)
                        cmd ="rpmbuild -ts --define \"_srcrpmdir {w}/{n}/src\" --define \"_dist %{nil}\" --define \"dist %{nil}\" {w}/{n}/src/{t} \
                                ".format(w=wdir, n=self.name, nil="{nil}", t=self.tarball)
                        rc, output = get_status_output(cmd)
                        self.log(f"{cmd}\n{output}")
                        if rc:
                            fatal("Failed to build the source RPM.\nCmd: {cmd}\n{output}\nExit status: {rc}".format(cmd=cmd, output=output, rc=rc))
                            return rc
                        self.src_rpm = glob.glob("{w}/{n}/src/*.src.rpm".format(w=wdir, n=self.name))[0].split(os.sep)[-1]
                        self.version = get_rpm_version("{w}/{n}/src/{s}".format(w=wdir, n=self.name, s=self.src_rpm))

    def install_package_dependencies(self):
        if self.os_build_dep:
            for p in self.os_build_dep:
                if not is_installed(p):
                    print("{} is not installed".format(p))
                    install_distro_package(p)
        if self.os_run_dep:
            for p in self.os_run_dep:
                if not is_installed(p):
                    print("{} is not installed".format(p))
                    install_distro_package(p)
        return 0

    def build_package(self):
        if self.bin:
            return 0

        if self.pre_build:
            rc, output = get_status_output(self.pre_build)
            self.log(f"{self.pre_build}\n{output}")
            if rc:
                fatal("Failed to run pre-build command {}\n{output}\nExit status: {rc}".format(self.pre_build, output=output, rc=rc))
                return rc

        if self.build_cmd:
            cmd = "test -d {w}/{n}/src && cd {w}/{n}/src || cd {w}/{n}; {env} KVER={k} KVERSION={k} {c}".format(env=self.env, w=wdir, n=self.name, k=kernel, c=self.build_cmd)
        else:
            if self.type == "user":
                if is_debian:
                    cmd = "cd {w}/{n}/src; \
                            {env} dpkg-buildpackage -b -us -uc".format(env=self.env, w=wdir, n=self.name)
                else:
                    cmd = "{env} rpmbuild --rebuild \
                            --define \"dist %{nil}\" \
                            --define \"_dist %{nil}\" \
                            --define \"_topdir {w}/{n}\" {w}/{n}/src/{s}".format(env=self.env, w=wdir, n=self.name, nil="{nil}", s=self.src_rpm)
            else:
                if is_debian:
                    cmd = "cd {w}/{n}/src; \
                            {env} KVER={k} KVERSION={k} dpkg-buildpackage -b -us -uc".format(env=self.env, w=wdir, n=self.name, k=kernel)
                else:
                    cmd = "{env} rpmbuild --rebuild \
                            --define \"KVERSION {k}\" \
                            --define \"dist %{nil}\" \
                            --define \"_dist %{nil}\" \
                            --define \"_topdir {w}/{n}\"".format(env=self.env, w=wdir, n=self.name, k=kernel, nil="{nil}")
                    if "bclinux" in kernel:
                        cmd += " --define \"KMP 0\""
                    elif "el7" in kernel or "el8" in kernel:
                        cmd += " --define \"KMP 1\""

                    cmd += " {w}/{n}/src/{s}".format(w=wdir, n=self.name, s=self.src_rpm)

        rc, output = get_status_output(cmd)
        self.log(f"{cmd}\n{output}")
        if rc:
            fatal("Failed to run:\n# {c}\n{output}\nExit status: {rc}".format(c=cmd, output=output, rc=rc))
            return rc

        # Removing debug package
        cmd = "/bin/rm -f {w}/{n}/RPMS/*/*debug*.rpm {w}/{n}/RPMS/*/*-doc*.rpm {w}/{n}/*dbg*.deb {w}/{n}/*.ddeb {w}/{n}/*-doc*.deb".format(w=wdir, n=self.name)
        rc, output = get_status_output(cmd)
        if rc:
            fatal("Failed to remove debug packages:\n{output}\nExit status: {rc}".format(output=output, rc=rc))
            return rc

        if self.post_build:
            rc, output = get_status_output(self.post_build)
            self.log(output)
            if rc:
                fatal("Failed to run post-build command {}\n{output}\nExit status: {rc}".format(self.post_build, output=output, rc=rc))
                return rc

    def install_package(self):
        if self.pre_install:
            rc, output = get_status_output(self.pre_install)
            self.log(f"{self.pre_install}\n{output}")
            if rc:
                fatal("Failed to run pre-install command {}\n{output}\nExit status: {rc}".format(self.pre_install, output=output, rc=rc))
                return rc

        if self.install_cmd:
            cmd = "cd {w}/{n}; {c}".format(w=wdir, n=self.name, c=self.install_cmd)
        else:
            if is_debian:
                cmd = "cd {w}/{n}; dpkg -i --force-all *.deb".format(w=wdir, n=self.name)
            else:
                if self.bin:
                    cmd = "rpm -iv --force --nodeps {w}/{n}/{b}".format(w=wdir, n=self.name, b=self.bin)
                else:
                    cmd = "rpm -iv --force --nodeps {w}/{n}/RPMS/*/*.rpm".format(w=wdir, n=self.name)

        rc, output = get_status_output(cmd)
        self.log(f"{cmd}\n{output}")
        if rc:
            fatal("Failed to run:\n# {c}\n{output}\nExit status: {rc}".format(c=cmd, output=output, rc=rc))
            return rc

        if self.post_install:
            rc, output = get_status_output(self.post_install)
            self.log(f"{self.post_install}\n{output}")
            if rc:
                fatal("Failed to run post-install command {}\n{output}\nExit status: {rc}".format(self.post_install, output=output, rc=rc))
                return rc
        self.is_installed = 1


def package_handler(package):
    if not AllPackages[package].is_available():
        fatal("Package {} is not available".format(package))
        return 1
    if AllPackages[package].skip_package():
        fatal("Package {} should be skipped".format(package))
        return 0
    if AllPackages[package].is_installed:
        info("Package {} is installed".format(package))
        return 0

    for req_package in AllPackages[package].internal_build_dep:
        debug("Package {req} is required by {p}".format(req=req_package, p=package))
        package_handler(req_package)

    for req_package in AllPackages[package].internal_run_dep:
        debug("Package {req} is required by {p}".format(req=req_package, p=package))
        package_handler(req_package)

    rc = AllPackages[package].install_package_dependencies()
    if rc:
        return rc
    get_retries = 0
    while get_retries < MAX_GET_RETRIES:
        rc = AllPackages[package].get_package()
        if rc:
            debug(f"Failed to get {package} on try {get_retries}")
            get_retries += 1
        else:
            debug(f"Succeeded to get {package} on retry {get_retries}")
            break
    if rc:
        return rc
    rc = AllPackages[package].build_package()
    if rc:
        fatal(f"ERROR: Failed to build {package}. RC={rc}")
        return rc
    rc = AllPackages[package].install_package()
    if rc:
        fatal(f"ERROR: Failed to install {package}. RC={rc}")
        return rc
    AllPackages[package].close_log()
    return 0


def main():
    global debug_enabled
    global distro
    global kernel
    passed_packages = {}
    failed_packages = {}
    rc = 0

    parser = argparse.ArgumentParser(description='Build and install packages for BFB image')
    parser.add_argument('--kernel', dest='kernel', help="Kernel version.")
    parser.add_argument('--skip-type-kernel', dest='skip_type_kernel', action='store_true', help="Skip kernel packages for SRU testing")
    parser.add_argument('--package', dest='package_to_install', help="Package to install. Others will be skipped")
    parser.add_argument('--debug', dest='debug_enabled', action='store_true', help="Enable debug output")
    parser.add_argument('--exit-on-failure', dest='exit_on_failure', action='store_true', help="Exit on failure")

    args = parser.parse_args()
    kernel = args.kernel
    debug_enabled = args.debug_enabled

    distro = get_distro()
    print(f"Distro: {distro} Kernel: {kernel}")

    if is_debian:
        rc, output = get_status_output("apt update")
        print(output)

    for p in DISTRO_REQUIRED_PACKAGES:
        if not is_installed(p):
            print("{} is not installed".format(p))
            install_distro_package(p)

    json_files = glob.glob("{}/*.json".format(manifests_dir))
    for j_file in json_files:
        print (f"Parsing: {j_file}")
        package = j_file.split(os.sep)[-1].replace('.json','')
        with open(j_file, encoding='utf-8') as conf:
            AllPackages[package] = Package(package, json.load(conf))
        print ("Name: {}".format(AllPackages[package].name))

    if args.package_to_install:
        package = args.package_to_install
        rc = package_handler(package)
        if rc:
            failed_packages[package] = AllPackages[package].version
        else:
            passed_packages[package] = AllPackages[package].version
    else:
        for package in AllPackages.keys():
            if AllPackages[package].type == "kernel" and args.skip_type_kernel:
                info(f"Skipping kenrel package {package}...")
                continue
            if not AllPackages[package].is_available():
                continue
            if AllPackages[package].skip_package():
                continue
            rc = package_handler(package)
            if rc:
                if args.exit_on_failure:
                    sys.exit(rc)
                failed_packages[package] = AllPackages[package].version
                info(f"Package {package} failed but continuing...")
            else:
                passed_packages[package] = AllPackages[package].version

    for p in DISTRO_PACKAGES2REMOVE:
        if not is_installed(p):
            print("{} is not installed".format(p))
            remove_distro_package(p)

    if passed_packages:
        print("#" * 80)
        print("PASSED packages:")
        for package in passed_packages.keys():
            print(f"{package}: {passed_packages[package]}")
        print("#" * 80)

    if failed_packages:
        print("#" * 80)
        print("FAILED packages:")
        for package in failed_packages.keys():
            print(f"{package}: {failed_packages[package]}")
        print("#" * 80)

    sys.exit(0)


if __name__ == "__main__":
    main()
