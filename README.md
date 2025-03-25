# NSC

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![ReportCard](https://goreportcard.com/badge/nats-io/nsc)](https://goreportcard.com/report/nats-io/nsc)
[![Build Status](https://github.com/nats-io/nsc/actions/workflows/pushes.yaml/badge.svg)](https://github.com/nats-io/nsc/actions/workflows/pushes.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nats-io/nsc/v2.svg)](https://pkg.go.dev/github.com/nats-io/nsc/v2)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/nsc/badge.svg?branch=main&service=github)](https://coveralls.io/github/nats-io/nsc?branch=main)

A tool for creating NATS account and user access configurations

## Install

This script downloads the latest released binary to the current working directory:
```
curl -sf https://binaries.nats.dev/nats-io/nsc/v2@latest | sh
```

With Python:

```bash
curl -L https://raw.githubusercontent.com/nats-io/nsc/main/install.py | python
```

Without Python and with a more cautious mindset:

```bash
curl -LO https://raw.githubusercontent.com/nats-io/nsc/main/install.sh
less install.sh
sh ./install.sh
```

With Homebrew:

```bash
brew tap nats-io/nats-tools
brew install nats-io/nats-tools/nsc

# to uninstall:
brew uninstall nats-io/nats-tools/nsc
brew untap nats-io/nats-tools
```

Direct Download:

Download your platform binary from
[GitHub releases.](https://github.com/nats-io/nsc/releases/latest)

## Updates are easy

`nsc update` will download and install the latest version. If you installed
using Homebrew, `brew update` will update.

## Documentation

[Documentation is here.](https://nats-io.github.io/nsc/)

## Running with Docker

The NATS team maintains a lightweight Docker image with many of the NATS
utilities called [nats-box](https://github.com/nats-io/nats-box) where `nsc` is
included. You can mount a local volume to get `nsc` accounts, nkeys, and other
config back on the host using Docker as follows:

```sh
docker run --rm -it -v $(pwd)/nsc:/nsc natsio/nats-box:latest

# In case NSC not initialized already:
nats-box:~# nsc init
nats-box:~# chown -R 1000:1000 /nsc
$ tree -L 2 nsc/
nsc/
 ├── accounts
 │   ├── nats
 │   └── nsc.json
 └── nkeys
    ├── creds
    └── keys

5 directories, 1 file
```
