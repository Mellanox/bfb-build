#!/usr/bin/env python3
###############################################################################
#
# Copyright 2026 NVIDIA Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
###############################################################################
"""Render a Dockerfile.j2 template into a Dockerfile.

The same template describes two build modes:

  default        - install the NVIDIA BlueField kernel pinned in <kernel-packages>
                   and the full doca-runtime / doca-devel metapackages.

  custom kernel  - skip the pinned kernel, install customer-supplied kernel .debs
                   instead, and use the doca-*-user metapackages so that no
                   prebuilt (kernel-version-pinned) DOCA kernel modules are
                   installed. MLNX_OFED is rebuilt against the custom kernel
                   later, by build_<distro>_bfb.

Usage:
    render_dockerfile.py --template Dockerfile.j2 --output Dockerfile \\
        [--custom-kernel] [--kernel-packages kernel-packages] \\
        [--ofed-src-tarball MLNX_OFED_SRC-debian-<ver>.tgz]
"""

import argparse
import os
import sys


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--template', default='Dockerfile.j2',
                   help='Jinja2 template to render (default: Dockerfile.j2)')
    p.add_argument('--output', default='Dockerfile',
                   help='Rendered Dockerfile path (default: Dockerfile)')
    p.add_argument('--custom-kernel', action='store_true',
                   help='Render the custom-kernel variant')
    p.add_argument('--kernel-packages', default='kernel-packages',
                   help='File listing the default kernel packages, one per line')
    p.add_argument('--ofed-src-tarball', default='',
                   help='Filename of the MLNX_OFED debian source tarball staged '
                        'next to the Dockerfile (custom-kernel mode only)')
    return p.parse_args()


def read_kernel_packages(path):
    """One package per line. Blank lines and # comments are ignored."""
    if not os.path.exists(path):
        return []
    packages = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.split('#', 1)[0].strip()
            if line:
                packages.append(line)
    return packages


def main():
    args = parse_args()

    try:
        from jinja2 import Environment, FileSystemLoader, StrictUndefined
    except ImportError:
        print("ERROR: python3 jinja2 module is required to render "
              "%s" % args.template, file=sys.stderr)
        print("Install it with one of:", file=sys.stderr)
        print("    apt install -y python3-jinja2", file=sys.stderr)
        print("    dnf install -y python3-jinja2", file=sys.stderr)
        print("    pip3 install jinja2", file=sys.stderr)
        sys.exit(1)

    kernel_packages = read_kernel_packages(args.kernel_packages)

    if not args.custom_kernel and not kernel_packages:
        print("ERROR: no kernel packages found in %s and --custom-kernel was "
              "not given" % args.kernel_packages, file=sys.stderr)
        sys.exit(1)

    if args.custom_kernel and not args.ofed_src_tarball:
        print("ERROR: --ofed-src-tarball is required with --custom-kernel",
              file=sys.stderr)
        sys.exit(1)

    template_dir = os.path.dirname(os.path.abspath(args.template)) or '.'
    env = Environment(loader=FileSystemLoader(template_dir),
                      undefined=StrictUndefined,
                      keep_trailing_newline=True,
                      trim_blocks=False,
                      lstrip_blocks=False)
    template = env.get_template(os.path.basename(args.template))

    rendered = template.render(custom_kernel=args.custom_kernel,
                               kernel_packages=kernel_packages,
                               ofed_src_tarball=args.ofed_src_tarball)

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(rendered)

    mode = 'custom kernel' if args.custom_kernel else 'default kernel'
    print("Rendered %s -> %s (%s)" % (args.template, args.output, mode))


if __name__ == '__main__':
    main()
