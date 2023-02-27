# NSC

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![ReportCard](https://goreportcard.com/badge/nats-io/nsc)](https://goreportcard.com/report/nats-io/nsc)
[![Build Status](https://github.com/nats-io/nsc/actions/workflows/pushes.yaml/badge.svg)](https://github.com/nats-io/nsc/actions/workflows/pushes.yaml)
[![GoDoc](http://godoc.org/github.com/nats-io/nsc?status.svg)](http://godoc.org/github.com/nats-io/nsc)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/nsc/badge.svg?branch=main&service=github)](https://coveralls.io/github/nats-io/nsc?branch=main)

A tool for creating NATS account and user access configurations

## Install

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
[here.](https://github.com/nats-io/nsc/releases/latest)

## Updates are easy

`nsc update` will download and install the latest version. If you installed
using Homebrew, `brew update` will update.

## Documentation

[Documentation is here.](https://nats-io.github.io/nsc/)

## Building

NSC uses go modules. If your project source is in `$GOPATH`, you must define set
the environment variable `GO111MODULE` to `on`.

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
