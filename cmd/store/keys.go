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

package store

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/nats-io/nkeys"
)

const DEfaultNKeysPath = ".nkeys"
const NKeysPathEnv = "NKEYS_PATH"
const NKeyExtension = "nk"

type NamedKey struct {
	Name string
	KP   nkeys.KeyPair
}

// Resolve a directory/file from an environment variable
// if not set defaultPath is returned
func ResolvePath(defaultPath string, varName string) string {
	v := os.Getenv(varName)
	if v != "" {
		return v
	}
	return defaultPath
}

func GetKeysDir() string {
	u, err := user.Current()
	if err != nil {
		return ResolvePath("", NKeysPathEnv)
	}
	return ResolvePath(filepath.Join(u.HomeDir, DEfaultNKeysPath), NKeysPathEnv)
}

// Resolve a key value provided as a flag - value could be an actual nkey or a path to an nkey
func ResolveKey(value string) (nkeys.KeyPair, error) {
	if value == "" {
		return nil, nil
	}
	d := []byte(value)
	kp, err := resolveAsKey(d)
	if err != nil {
		kp, err = keyFromFile(value)
		if err != nil {
			return nil, err
		}
	}
	return kp, nil
}

type KeyStore struct {
	Env string
}

func NewKeyStore(environmentName string) KeyStore {
	return KeyStore{Env: environmentName}
}

func (k *KeyStore) keyName(n string) string {
	return fmt.Sprintf("%s.%s", n, NKeyExtension)
}

func (k *KeyStore) keypath(name string, kp nkeys.KeyPair, parent string) (string, error) {
	kt, err := KeyType(kp)
	if err != nil {
		return "", err
	}
	switch kt {
	case nkeys.PrefixByteOperator:
		return filepath.Join(GetKeysDir(), k.Env, k.keyName(name)), nil
	case nkeys.PrefixByteAccount:
		return filepath.Join(GetKeysDir(), k.Env, Accounts, name, k.keyName(name)), nil
	case nkeys.PrefixByteUser:
		if parent == "" {
			return "", fmt.Errorf("user keys require an account parent")
		}
		return filepath.Join(GetKeysDir(), k.Env, Accounts, parent, Users, k.keyName(name)), nil
	case nkeys.PrefixByteCluster:
		return filepath.Join(GetKeysDir(), k.Env, Clusters, name, k.keyName(name)), nil
	case nkeys.PrefixByteServer:
		if parent == "" {
			return "", fmt.Errorf("servers keys require a cluster parent")
		}
		return filepath.Join(GetKeysDir(), k.Env, Clusters, parent, Servers, k.keyName(name)), nil
	default:
		return "", nil
	}
}

func (k *KeyStore) GetOperatorKey(name string) (nkeys.KeyPair, error) {
	return ResolveKey(filepath.Join(GetKeysDir(), k.Env, k.keyName(name)))
}

func (k *KeyStore) GetAccountKey(operator string, name string) (nkeys.KeyPair, error) {
	return ResolveKey(filepath.Join(GetKeysDir(), k.Env, Accounts, name, k.keyName(name)))
}

func (k *KeyStore) GetUserKey(operator string, account string, name string) (nkeys.KeyPair, error) {
	return ResolveKey(filepath.Join(GetKeysDir(), k.Env, Accounts, account, Users, k.keyName(name)))
}

func (k *KeyStore) GetClusterKey(operator string, name string) (nkeys.KeyPair, error) {
	return ResolveKey(filepath.Join(GetKeysDir(), k.Env, Clusters, name, k.keyName(name)))
}

func (k *KeyStore) GetServerKey(operator string, cluster string, name string) (nkeys.KeyPair, error) {
	return ResolveKey(filepath.Join(GetKeysDir(), k.Env, Clusters, cluster, Servers, k.keyName(name)))
}

func (k *KeyStore) Store(keyname string, kp nkeys.KeyPair, parent string) (string, error) {
	fp, err := k.keypath(keyname, kp, parent)
	if err != nil {
		return "", err
	}

	seed, err := kp.Seed()
	if err != nil {
		return "", fmt.Errorf("error reading seed from nkey: %v", err)
	}

	_, err = os.Stat(filepath.Dir(fp))
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		err = os.MkdirAll(filepath.Dir(fp), 0700)
		if err != nil {
			return "", err
		}
	}
	_, err = os.Stat(fp)
	if err != nil {
		if os.IsNotExist(err) {
			err := ioutil.WriteFile(fp, seed, 0600)
			if err != nil {
				return "", fmt.Errorf("error writing %q: %v", fp, err)
			}
			return fp, nil
		}
	}
	d, err := ioutil.ReadFile(fp)
	if err != nil {
		return "", fmt.Errorf("error reading %q: %v", fp, err)
	}
	if string(d) != string(seed) {
		return "", fmt.Errorf("key %q already exists and is different", keyname)
	}
	return "", nil
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
	kp, err := resolveAsKey(d)
	if err != nil {
		return nil, err
	}

	return kp, nil
}

func resolveAsKey(d []byte) (nkeys.KeyPair, error) {
	kp, err := nkeys.FromSeed(d)
	if err == nil {
		return kp, nil
	}

	kp, err = nkeys.FromPublicKey(d)
	if err == nil {
		return kp, nil
	}
	return kp, err
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

type KeyTypeFn func([]byte) bool

func KeyPairTypeOk(kind nkeys.PrefixByte, kp nkeys.KeyPair) bool {
	d, _ := kp.PublicKey()
	return IsPublicKey(kind, d)
}

func IsPublicKey(kind nkeys.PrefixByte, key []byte) bool {
	var f KeyTypeFn
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

func KeyType(kp nkeys.KeyPair) (nkeys.PrefixByte, error) {
	d, err := kp.PublicKey()
	if err != nil {
		return 0, err
	}
	if nkeys.IsValidPublicOperatorKey(d) {
		return nkeys.PrefixByteOperator, nil
	}
	if nkeys.IsValidPublicAccountKey(d) {
		return nkeys.PrefixByteAccount, nil
	}
	if nkeys.IsValidPublicClusterKey(d) {
		return nkeys.PrefixByteCluster, nil
	}
	if nkeys.IsValidPublicServerKey(d) {
		return nkeys.PrefixByteServer, nil
	}
	if nkeys.IsValidPublicUserKey(d) {
		return nkeys.PrefixByteUser, nil
	}
	return 0, fmt.Errorf("unsupported key type")
}
