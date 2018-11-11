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
	"os/user"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
)

var KeyPathFlag string

const DefaultNkeysPath = ".nkeys"

func GetKeysDir() string {
	u, err := user.Current()
	if err != nil {
		return ResolvePath("", NkeysPathEnv)
	}
	return ResolvePath(filepath.Join(u.HomeDir, DefaultNkeysPath), NkeysPathEnv)
}

func ResolveKeyFlag() (nkeys.KeyPair, error) {
	if KeyPathFlag != "" {
		kp, err := resolveKey(KeyPathFlag)
		if err != nil {
			return nil, err
		}
		return kp, nil
	}
	return nil, nil
}

type KeyStore struct {
}

func NewKeyStore() *KeyStore {
	return &KeyStore{}
}

func (k *KeyStore) Store(name string, kp nkeys.KeyPair) error {
	dir := GetKeysDir()
	p, err := kp.PublicKey()
	if err != nil {
		return fmt.Errorf("error reading public from nkey: %v", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		return fmt.Errorf("error reading seed from nkey: %v", err)
	}

	sd := string(p[0])

	if name == "" {
		name = string(p)
	}
	fp := filepath.Join(dir, sd)
	_, err = os.Stat(fp)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		err = os.MkdirAll(fp, 0700)
		if err != nil {
			return err
		}
	}

	fp = filepath.Join(fp, fmt.Sprintf("%s.nk", name))
	_, err = os.Stat(fp)
	if err != nil {
		if os.IsNotExist(err) {
			err := ioutil.WriteFile(fp, seed, 0600)
			if err != nil {
				return fmt.Errorf("error writing %q: %v", fp, err)
			}
			return nil
		}
	}
	d, err := ioutil.ReadFile(fp)
	if err != nil {
		return fmt.Errorf("error reading %q: %v", fp, err)
	}
	if string(d) != string(seed) {
		return fmt.Errorf("key %q already exists and is different", fp)
	}
	return nil
}

func (k *KeyStore) FindSeed(pubkey string) (nkeys.KeyPair, error) {
	kp, err := ResolveKeyFlag()
	if err != nil {
		return nil, err
	}
	if kp != nil {
		if Match(pubkey, kp) {
			return kp, nil
		}
	}

	dir := GetKeysDir()
	sd := string(pubkey[0])
	fp := filepath.Join(dir, sd)
	keys, err := k.getKeys(fp)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if Match(pubkey, k) {
			return k, nil
		}
	}
	return nil, nil
}

func (k *KeyStore) getKeys(dir string) ([]nkeys.KeyPair, error) {
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var keys []nkeys.KeyPair
	for _, v := range infos {
		n := strings.ToLower(v.Name())
		if strings.HasSuffix(n, ".nk") {
			fp := filepath.Join(dir, v.Name())
			kp, err := keyFromFile(fp)
			if err != nil {
				return nil, fmt.Errorf("error parsing file from %q: %v", fp, err)
			}
			keys = append(keys, kp)
		}
	}
	return keys, nil
}

func (k *KeyStore) GetAllKeys() ([]nkeys.KeyPair, error) {
	dir := GetKeysDir()

	var keys []nkeys.KeyPair

	kinds := []string{"O", "A", "U", "N", "C"}
	for _, k := range kinds {
		keyDir := filepath.Join(dir, k)
		_, err := os.Stat(keyDir)
		if os.IsNotExist(err) {
			continue
		}

		infos, err := ioutil.ReadDir(keyDir)
		if err != nil {
			return nil, err
		}

		for _, v := range infos {
			n := strings.ToLower(v.Name())
			if strings.HasSuffix(n, ".nk") {
				fp := filepath.Join(keyDir, v.Name())
				kp, err := keyFromFile(fp)
				if err != nil {
					return nil, fmt.Errorf("error parsing file from %q: %v", fp, err)
				}
				keys = append(keys, kp)
			}
		}
	}
	return keys, nil
}

func Match(pubkey string, kp nkeys.KeyPair) bool {
	pk, err := kp.PublicKey()
	if err != nil {
		return false
	}
	if pubkey != string(pk) {
		return false
	}

	return true
}

func keyFromFile(path string) (nkeys.KeyPair, error) {
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kp, err := nkeys.FromSeed(d)
	if err != nil {
		return nil, err
	}
	return kp, nil
}

func resolveKey(value string) (nkeys.KeyPair, error) {
	kp, err := nkeys.FromSeed([]byte(value))
	if err != nil {
		kp, err = keyFromFile(value)
		if err != nil {
			return nil, err
		}
	}
	return kp, nil
}

type NKeyFactory func() (nkeys.KeyPair, error)

func CreateNKey(kind nkeys.PrefixByte) (nkeys.KeyPair, error) {
	var f NKeyFactory
	switch kind {
	case nkeys.PrefixByteAccount:
		f = nkeys.CreateAccount
	case nkeys.PrefixByteCluster:
		f = nkeys.CreateCluster
	case nkeys.PrefixByteOperator:
		f = nkeys.CreateOperator
	case nkeys.PrefixByteServer:
		f = nkeys.CreateServer
	case nkeys.PrefixByteUser:
		f = nkeys.CreateUser
	default:
		return nil, fmt.Errorf("unexpected kind %d", kind)
	}

	return f()
}

type KeyType func([]byte) bool

func IsPublicKey(kind nkeys.PrefixByte, key []byte) bool {
	var f KeyType
	switch kind {
	case nkeys.PrefixByteAccount:
		f = nkeys.IsValidPublicAccountKey
	case nkeys.PrefixByteCluster:
		f = nkeys.IsValidPublicClusterKey
	case nkeys.PrefixByteOperator:
		f = nkeys.IsValidPublicOperatorKey
	case nkeys.PrefixByteServer:
		f = nkeys.IsValidPublicServerKey
	case nkeys.PrefixByteUser:
		f = nkeys.IsValidPublicUserKey
	default:
		return false
	}
	return f(key)
}

func KeyTypeLabel(kind nkeys.PrefixByte) string {
	switch kind {
	case nkeys.PrefixByteAccount:
		return "account"
	case nkeys.PrefixByteCluster:
		return "cluster"
	case nkeys.PrefixByteOperator:
		return "operator"
	case nkeys.PrefixByteServer:
		return "server"
	case nkeys.PrefixByteUser:
		return "user"
	default:
		return ""
	}
}
