# NSC

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![ReportCard](http://goreportcard.com/badge/nats-io/nsc)](http://goreportcard.com/report/nats-io/nsc)
[![Build Status](https://travis-ci.org/nats-io/nsc.svg?branch=master)](http://travis-ci.org/nats-io/nsc)
[![GoDoc](http://godoc.org/github.com/nats-io/nsc?status.svg)](http://godoc.org/github.com/nats-io/nsc)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/nsc/badge.svg?branch=master&service=github)](https://coveralls.io/github/nats-io/nsc?branch=master)

A tool for creating NATS account and user access configurations


## Install

With Python:

```python
curl -L https://raw.githubusercontent.com/nats-io/nsc/master/install.py | python
```

Direct Download:

Download your platform binary from [here.](https://github.com/nats-io/nsc/releases/latest)

## Updates are easy

`nsc update` will download and install the latest version.

## Building

NSC uses go modules. If your project source is in `$GOPATH`, you must define set the environment variable `GO111MODULE` to `on`.

