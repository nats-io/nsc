#!/usr/bin/env python

# Copyright 2018-2021 The NATS Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This installer mostly inspired by
# https://github.com/denoland/deno_install/blob/master/install.py

from __future__ import print_function

import io
import os
import re
import sys
import zipfile
import zlib

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

NSC_REPO_URL = "https://github.com/nats-io/nsc"
FILENAME_LOOKUP = {
    "darwin": {
        "amd64": "nsc-darwin-amd64.zip",
        "arm64": "nsc-darwin-arm64.zip",
    },
    "linux": {
        "amd64": "nsc-linux-amd64.zip",
        "arm64": "nsc-linux-arm64.zip",
    },
    "win32": {
        "amd64": "nsc-windows-amd64.zip",
    },
}


def release_url(platform, arch, tag):
    if "linux" in platform:
        # convert any linux regardless of version reported to "linux"
        platform = "linux"
    if arch == "x86_64":
        arch = "amd64"
    elif arch == "aarch64":
        arch = "arm64"
    try:
        filename = FILENAME_LOOKUP[platform][arch]
    except KeyError:
        print("Unable to locate appropriate filename for", platform, "with archtecture", arch)
        sys.exit(1)

    release_base = NSC_REPO_URL + '/releases/'
    if tag:
        return release_base + 'download/' + tag + '/' + filename
    return release_base + 'latest/download/' + filename


def download_with_progress(url):
    print("Downloading", url)

    remote_file = urlopen(url)
    total_size = int(remote_file.headers['Content-Length'].strip())

    data = []
    bytes_read = 0.0

    while True:
        d = remote_file.read(8192)

        if not d:
            print()
            break

        bytes_read += len(d)
        data.append(d)
        sys.stdout.write('\r%2.2f%% downloaded' % (bytes_read / total_size * 100))
        sys.stdout.flush()

    return b''.join(data)


def main():
    url = release_url(sys.platform, os.uname()[4], sys.argv[1] if len(sys.argv) > 1 else None)
    bin_dir = nsc_bin_dir()
    exe_fn = os.path.join(bin_dir, "nsc")
    windows = "windows" in url
    if windows:
        exe_fn = os.path.join(bin_dir, "nsc.exe")

    compressed = download_with_progress(url)
    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(compressed), 'r') as z:
            with open(exe_fn, 'wb+') as exe:
                if windows:
                    exe.write(z.read('nsc.exe'))
                else:
                    exe.write(z.read('nsc'))
    else:
        # Note: gzip.decompress is not available in python2.
        content = zlib.decompress(compressed, 15 + 32)
        with open(exe_fn, 'wb+') as exe:
            exe.write(content)
    os.chmod(exe_fn, 0o744)

    print("NSC: " + exe_fn)
    if maybe_symlink(exe_fn):
        return

    print("Now manually add %s to your $PATH" % bin_dir)
    if windows:
        print("Windows Cmd Prompt Example:")
        print("  setx path %%path;\"%s\"" % bin_dir)
        print()
    else:
        print("Bash Example:")
        print("  echo 'export PATH=\"$PATH:%s\"' >> $HOME/.bashrc" % bin_dir)
        print("  source $HOME/.bashrc")
        print()
        print("Zsh Example:")
        print("  echo 'export PATH=\"$PATH:%s\"' >> $HOME/.zshrc" % bin_dir)
        print("  source $HOME/.zshrc")
        print()


# Returns True if install instructions are not needed
def maybe_symlink(exe_fn):
    sym_dir = nsc_symlink_dir()
    if not sym_dir:
        return False
    link_path = os.path.join(sym_dir, os.path.basename(exe_fn))
    if os.path.exists(link_path):
        if os.path.islink(link_path):
            try:
                os.unlink(link_path)
            except Exception:
                return False
        else:
            print("Not touching non-symlink: " + link_path)
            return False
    try:
        os.symlink(exe_fn, link_path)
        print("NSC: " + link_path)
        if dir_in_PATH(sym_dir):
            return True
        return False
    except Exception:
        # Python2 does not support symlinks on Windows, amongst other
        # reasons this might have failed.
        return False


def dir_in_PATH(dirname):
    try:
        envPath = os.environ['PATH']
    except Exception:
        return False
    return dirname in envPath.split(os.pathsep)


def mkdir(d):
    if not os.path.exists(d):
        print("mkdir", d)
        os.mkdir(d)


def nsc_bin_dir():
    home = os.path.expanduser("~")
    nsccli = os.path.join(home, ".nsccli")
    mkdir(nsccli)
    bin_dir = os.path.join(nsccli, "bin")
    mkdir(bin_dir)
    return bin_dir


def nsc_symlink_dir():
    home = os.path.expanduser("~")
    sym_dir = os.path.join(home, "bin")
    if os.path.exists(sym_dir):
        return sym_dir
    return None


if __name__ == '__main__':
    main()
