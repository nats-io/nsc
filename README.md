# NSC Package

This branch exists to track progress on pulling `nsc` out to a reusable go package so others can build systems that interact with NATS decentralized Auth.

Package design proposal:

```go
package main

import (
	"errors"
	"log"
	"strings"

	"github.com/nats-io/jwt/v2"
)

type Entity struct {
	Name      string
	PublicKey string
}

type Status struct {
	status []string
}

func (s *Status) AddStatus(status string) {
	s.status = append(s.status, status)
}

type User struct {
	Entity
	Status
	Claims *jwt.UserClaims
}

type UserOpt func(u *User) error

type UserManager interface {
	GetUsers() ([]User, error)
	GetUser(name string) (*User, error)

	CreateUser(name string, opts ...UserOpt) (*User, error)
	UpdateUser(name string, opts ...UserOpt) (*User, error)
	DeleteUser(name string, opts ...UserOpt) (*User, error)

	ImportUser(jwt string, publicKey string, seed []byte) (*User, error)
}

type Account struct {
	Entity
	Status
	Claims *jwt.AccountClaims
}

type AccountOpt func(a *Account) error

type AccountManager interface {
	GetAccounts() ([]Account, error)
	GetAccount(name string) (*Account, error)

	CreateAccount(name string, opts ...AccountOpt) (*Account, error)
	UpdateAccount(name string, opts ...AccountOpt) (*Account, error)
	DeleteAccount(name string, opts ...AccountOpt) (*Account, error)

	ImportAccount(jwt string, publicKey string, seed []byte) (*Account, error)
}

type Operator struct {
	Entity
	Status
	Claims *jwt.OperatorClaims
}

type OperatorOpt func(o *Operator) error

type OperatorManager interface {
	GetOperators() ([]Operator, error)
	GetOperator(name string) (*Operator, error)

	CreateOperator(name string, opts ...OperatorOpt) (*Operator, error)
	UpdateOperator(name string, opts ...OperatorOpt) (*Operator, error)
	DeleteOperator(name string, opts ...OperatorOpt) (*Operator, error)

	ImportOperator(jwt string, publicKey string, seed []byte) (*Operator, error)
}

type Manager interface {
	UserManager
	AccountManager
	OperatorManager

	Operator() Entity
	SetOperator(Entity)

	Account() Entity
	SetAccount(Entity)
}

type Store interface {
	Get(path string) (jwt string, err error)
	Put(path string, jwt string) error
	List(path string) (jwts []string, err error)
	Delete(path string) error
}

type KeyStore interface {
	Get(publicKey string) (seed []byte, err error)
	Put(publicKey string, seed []byte) error
	Delete(publicKey string) (seed []byte, err error)
}

type Config struct {
	Operator Entity
	Account  Entity
	Store
	KeyStore
}

func New(ctx *Config) (Manager, error) {
	return nil, errors.New("not implemented")
}

func PubAllow(subjects ...string) UserOpt {
	return func(u *User) error {
		u.Claims.Pub.Allow = jwt.StringList(subjects)
		u.AddStatus("Added puballow for " + strings.Join(subjects, ", "))
		return nil
	}
}

func main() {
	// Just a stupid example around creating an operator and an account/user
	nsc, _ := New(&Config{})

	operator, _ := nsc.CreateOperator("my_operator")
	nsc.SetOperator(operator.Entity)

	account, _ := nsc.CreateAccount("TEAM_A", func(a *Account) (err error) {
		a.Claims.DefaultPermissions.Pub.Allow.Add("math.double")

		a.AddStatus("Added pubs and subs")

		return nil
	})
	nsc.SetAccount(account.Entity)

	user, _ := nsc.CreateUser("my_user", PubAllow("foo.bar", "bat.baz"))

	log.Println(user)
}
```

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
docker run --rm -it -v $(pwd)/nsc:/nsc synadia/nats-box:latest

# In case NSC not initialized already:
nats-box:~# nsc init
nats-box:~# chmod -R 1000:1000 /nsc
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
