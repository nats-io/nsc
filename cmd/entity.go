/*
 * Copyright 2018 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
)

type Entity interface {
	Kind() nkeys.PrefixByte
	Load() error
	ParentKey() (string, error)
	Store() error
}

type Entry struct {
	claim         jwt.Claims
	containerPath string
	kind          nkeys.PrefixByte
	name          string
	store         *store.Store
}

func (e *Entry) fileName() string {
	return fmt.Sprintf("%s.jwt", e.name)
}

func (e *Entry) Load() error {
	d, err := e.store.Read(e.containerPath, e.fileName())
	e.claim, err = jwt.DecodeGeneric(string(d))
	return err
}

func (e *Entry) Save() error {
	ppk, err := e.ParentKey()
	kp, err := NewKeyStore().FindSeed(ppk)
	if err != nil {
		return fmt.Errorf("error resolving public key %q: %v", ppk, err)
	}
	if kp == nil {
		return fmt.Errorf("error find private key for %q", ppk)
	}

	cd, err := e.claim.Encode(kp)
	return e.store.Write([]byte(cd), e.containerPath, e.fileName())
}

func (e *Entry) Kind() nkeys.PrefixByte {
	return e.kind
}

func (e *Entry) ParentType() nkeys.PrefixByte {
	var pre nkeys.PrefixByte = 255
	switch e.kind {
	case nkeys.PrefixByteAccount:
		return nkeys.PrefixByteOperator
	case nkeys.PrefixByteUser:
		return nkeys.PrefixByteAccount
	case nkeys.PrefixByteCluster:
		return nkeys.PrefixByteOperator
	case nkeys.PrefixByteServer:
		return nkeys.PrefixByteCluster
	}
	return pre
}

func (e *Entry) ParentKey() (string, error) {
	var parentPath string
	switch e.kind {
	case nkeys.PrefixByteCluster:
		fallthrough
	case nkeys.PrefixByteAccount:
		parentPath = "../../.."
	case nkeys.PrefixByteServer:
		fallthrough
	case nkeys.PrefixByteUser:
		parentPath = "../.."
	default:
		return "", fmt.Errorf("unknown parent for prefix: %d", e.kind)
	}

	pp := filepath.Join(e.containerPath, parentPath)
	fi, err := os.Stat(pp)
	if err != nil {
		return "", fmt.Errorf("unable to find parent for %q - expected at %q", e.containerPath, pp)
	}
	pf := filepath.Join(pp, fmt.Sprintf("%s.jwt", fi.Name()))
	_, err = os.Stat(pf)
	if err != nil {
		return "", fmt.Errorf("%q is not found", pf)
	}
	pd, err := ioutil.ReadFile(pf)
	if err != nil {
		return "", fmt.Errorf("error reading %q: %v", pf, err)
	}

	gc, err := jwt.DecodeGeneric(string(pd))
	if err != nil {
		return "", fmt.Errorf("error decoding jwt %q: %v", pf, err)
	}

	return gc.Subject, nil
}
