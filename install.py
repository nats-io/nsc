#!/usr/bin/env python

# Copyright 2018 The NATS Authors
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
LATEST_RELEASE_URL = NSC_REPO_URL + "/releases/latest"
TAG_URL = NSC_REPO_URL + "/releases/tag/"
FILENAME_LOOKUP = {
    "darwin": "nsc-darwin-amd64.zip",
    "linux": "nsc-linux-amd64.zip",
    "win32": "nsc-windows-amd64.zip"
}


def release_url(platform, tag):
    try:
        filename = FILENAME_LOOKUP[platform]
    except KeyError:
        print("Unable to locate appropriate filename for", platform)
        sys.exit(1)

    url = TAG_URL + tag if tag else LATEST_RELEASE_URL

    try:
        html = urlopen(url).read().decode('utf-8')
    except:
        print("Unable to find release page for", tag)
        sys.exit(1)

    urls = re.findall(r'href=[\'"]?([^\'" >]+)', html)
    matching = [u for u in urls if filename in u]

    if len(matching) != 1:
        print("Unable to find download url for", filename)
        sys.exit(1)

    return "https://github.com" + matching[0]


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
    bin_dir = nsc_bin_dir()
    exe_fn = os.path.join(bin_dir, "nsc")

    url = release_url(sys.platform, sys.argv[1] if len(sys.argv) > 1 else None)
    compressed = download_with_progress(url)

    if url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(compressed), 'r') as z:
            with open(exe_fn, 'wb+') as exe:
                if "windows" not in url:
                    exe.write(z.read('nsc'))
                else:
                    exe.write(z.read('nsc.exe'))
    else:
        # Note: gzip.decompress is not available in python2.
        content = zlib.decompress(compressed, 15 + 32)
        with open(exe_fn, 'wb+') as exe:
            exe.write(content)
    os.chmod(exe_fn, 0o744)

    print("NSC: " + exe_fn)
    print("Now manually add %s to your $PATH" % bin_dir)
    print("Example:")
    print()
    print("  echo export PATH=\"%s\":\\$PATH >> $HOME/.bash_profile" % bin_dir)
    print()


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


if __name__ == '__main__':
    main()