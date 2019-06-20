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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/nats-io/nuid"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nkeys"
)

const DEfaultNKeysPath = ".nkeys"
const NKeysPathEnv = "NKEYS_PATH"
const NKeyExtension = "nk"
const CredsExtension = "creds"
const CredsDir = "creds"
const KeysDir = "keys"

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

func KeysNeedMigration() (bool, error) {
	dir := GetKeysDir()
	ok, err := dirExists(dir)
	if err != nil || !ok {
		return false, err
	}
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		return false, err
	}
	if len(infos) == 0 {
		return false, nil
	}
	ok, err = fileExists(filepath.Join(dir, KeysDir))
	return !ok, err
}

func Migrate() (string, error) {
	dir := GetKeysDir()
	// make a new directory next to it
	name := nuid.Next()
	to := filepath.Join(filepath.Dir(dir), name)
	if err := MaybeMakeDir(to); err != nil {
		return "", err
	}
	if err := AddGitIgnore(to); err != nil {
		return "", err
	}
	if err := MaybeMakeDir(filepath.Join(to, KeysDir)); err != nil {
		return "", err
	}
	if err := MaybeMakeDir(filepath.Join(to, CredsDir)); err != nil {
		return "", err
	}
	// migrate the keys and creds
	_, _, err := migrateKeyStore(dir, to)
	if err != nil {
		return "", err
	}
	// rename the old dir
	old := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+"_"+name)
	if err := os.Rename(dir, old); err != nil {
		return "", err
	}
	// rename new
	if err := os.Rename(to, dir); err != nil {
		return "", err
	}
	return old, nil
}

func (k *KeyStore) credsName(n string) string {
	return fmt.Sprintf("%s.%s", n, CredsExtension)
}

func (k *KeyStore) keyName(n string) string {
	return fmt.Sprintf("%s.%s", n, NKeyExtension)
}

func (k *KeyStore) CalcUserCredsPath(account string, user string) string {
	return filepath.Join(GetKeysDir(), CredsDir, k.Env, Accounts, account, k.credsName(user))

}

func (k *KeyStore) GetUserCredsPath(account string, user string) string {
	fp := k.CalcUserCredsPath(account, user)
	if _, err := os.Stat(fp); err != nil {
		return ""
	}
	return fp
}

func (k *KeyStore) MaybeStoreUserCreds(account string, user string, data []byte) (string, error) {
	kp, err := ExtractSeed(string(data))
	if err != nil {
		return "", fmt.Errorf("unable to store user creds file - error reading creds data: %v", err)
	}

	pk, err := kp.PublicKey()
	if err != nil {
		return "", fmt.Errorf("unable to get the public key from the seed in the creds: %v", err)
	}

	_, err = k.GetKeyPair(pk)
	if os.IsNotExist(err) {
		return "", errors.New("unable to store creds file - user's seed file is not in the keystore")
	}
	if err != nil {
		return "", fmt.Errorf("unable to store creds file - error examining user's seed file: %v", err)
	}

	fp := k.CalcUserCredsPath(account, user)
	dir := filepath.Dir(fp)
	if err := MaybeMakeDir(dir); err != nil {
		return "", err
	}
	if err := AddGitIgnore(dir); err != nil {
		return "", err
	}

	return fp, ioutil.WriteFile(fp, data, 0600)
}

func (k *KeyStore) keypath(kp nkeys.KeyPair) (string, error) {
	pk, err := kp.PublicKey()
	if err != nil {
		return "", err
	}
	return k.GetKeyPath(pk), nil
}

func (k *KeyStore) GetKeyPath(pubkey string) string {
	kind := pubkey[0:1]
	shard := pubkey[1:3]
	return filepath.Join(GetKeysDir(), KeysDir, kind, shard, fmt.Sprintf("%s.nk", pubkey))
}

func (k *KeyStore) GetKeyPair(pubkey string) (nkeys.KeyPair, error) {
	return k.Read(k.GetKeyPath(pubkey))
}

func (k *KeyStore) GetPublicKey(pubkey string) (string, error) {
	return k.getPublicKey(k.GetKeyPair(pubkey))
}

func (k *KeyStore) GetSeed(pubkey string) (string, error) {
	return k.getSeed(k.GetKeyPair(pubkey))
}

func (k *KeyStore) getPublicKey(kp nkeys.KeyPair, err error) (string, error) {
	return kp.PublicKey()
}

func (k *KeyStore) getSeed(kp nkeys.KeyPair, err error) (string, error) {
	if err != nil {
		return "", err
	}
	d, err := kp.Seed()
	if err != nil {
		return "", err
	}
	return string(d), nil
}


func AddGitIgnore(dir string) error {
	if dir != "" {
		_, err := os.Stat(dir)
		if err != nil {
			return nil
		}
		ignoreFile := filepath.Join(dir, ".gitignore")
		_, err = os.Stat(ignoreFile)
		if os.IsNotExist(err) {
			d := `# ignore all nk files
**/*.nk

# ignore all creds files
**/*.creds
`
			return ioutil.WriteFile(ignoreFile, []byte(d), 0600)
		}
	}
	return nil
}

func (k *KeyStore) store(fp string, kp nkeys.KeyPair) (string, error) {
	seed, err := kp.Seed()
	if err != nil {
		return "", fmt.Errorf("error reading seed from nkey: %v", err)
	}

	dir := filepath.Dir(fp)
	err = MaybeMakeDir(dir)
	AddGitIgnore(dir)

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
		return "", fmt.Errorf("key %q already exists and is different", fp)
	}
	return "", nil
}

func (k *KeyStore) Store(kp nkeys.KeyPair) (string, error) {
	fp, err := k.keypath(kp)
	if err != nil {
		return "", err
	}
	return k.store(fp, kp)
}

func (k *KeyStore) Read(path string) (nkeys.KeyPair, error) {
	return keyFromFile(path)
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

func dataFromFile(path string) ([]byte, error) {
	var err error
	path, err = homedir.Expand(path)
	if err != nil {
		return nil, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		} else {
			return nil, err
		}
	}
	return ioutil.ReadFile(path)
}

func keyFromFile(path string) (nkeys.KeyPair, error) {
	d, err := dataFromFile(path)
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
	if d == nil {
		return nil, nil
	}
	kp, err := nkeys.FromSeed(d)
	if err == nil {
		return kp, nil
	}

	kp, err = nkeys.FromPublicKey(string(d))
	if err == nil {
		return kp, nil
	}
	return kp, err
}

type NKeyFactory func() (nkeys.KeyPair, error)

type KeyTypeFn func(string) bool

func KeyPairTypeOk(kind nkeys.PrefixByte, kp nkeys.KeyPair) bool {
	d, _ := kp.PublicKey()
	return IsPublicKey(kind, d)
}

func IsPublicKey(kind nkeys.PrefixByte, key string) bool {
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

func dirExists(fp string) (bool, error) {
	fi, err := os.Stat(fp)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.IsDir() {
		return true, nil
	} else {
		return false, fmt.Errorf("%q is not a directory", fp)
	}
}

func fileExists(fp string) (bool, error) {
	fi, err := os.Stat(fp)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.IsDir() {
		return false, fmt.Errorf("%q is not a file", fp)
	} else {
		return true, nil
	}
}

func migrateKeyStore(from string, to string) (keys []string, creds []string, err error) {
	if err := MaybeMakeDir(to); err != nil {
		return nil, nil, err
	}
	if err := MaybeMakeDir(filepath.Join(to, "keys")); err != nil {
		return nil, nil, err
	}
	if err := MaybeMakeDir(filepath.Join(to, "creds")); err != nil {
		return nil, nil, err
	}

	err = filepath.Walk(from, func(src string, info os.FileInfo, err error) error {
		ext := filepath.Ext(src)
		switch ext {
		case ".nk":
			fp, err := migrateKey(src, to)
			if err != nil {
				return err
			}
			if fp == "" {
				return nil
			}
			keys = append(keys, fp)
		case ".creds":
			fp, err := migrateCreds(src, to)
			if err != nil {
				return err
			}
			if fp == "" {
				return nil
			}
			creds = append(creds, fp)
		}
		return nil
	})
	return keys, creds, err
}

func migrateKey(src string, to string) (string, error) {
	if filepath.Ext(src) == ".nk" {
		d, err := dataFromFile(src)
		if err != nil {
			return "", fmt.Errorf("error processing %q: %v", src, err)
		}
		kp, err := nkeys.FromSeed(d)
		if err != nil {
			return "", fmt.Errorf("error processing %q: %v", src, err)
		}

		pk, err := kp.PublicKey()
		if err != nil {
			return "", fmt.Errorf("error processing %q: %v", src, err)
		}
		kind := pk[0:1]
		shard := pk[1:3]

		fp := filepath.Join(to, "keys", kind, shard, fmt.Sprintf("%s.nk", pk))
		if err := MaybeMakeDir(filepath.Dir(fp)); err != nil {
			return "", err
		}
		return fp, Write(fp, d)
	}
	return "", nil
}

func migrateCreds(src string, to string) (string, error) {
	if filepath.Ext(src) == ".creds" {
		d, err := dataFromFile(src)
		if err != nil {
			return "", fmt.Errorf("error processing %q: %v", src, err)
		}
		name := filepath.Base(src)
		// parent is users, grab the account
		account := filepath.Base(filepath.Dir(filepath.Dir(src)))
		// grand parent is operator
		operator := filepath.Base(filepath.Dir(account))

		to := filepath.Join(to, "creds", operator, account, name)
		if err := MaybeMakeDir(filepath.Dir(to)); err != nil {
			return "", err
		}

		return to, Write(to, d)
	}
	return "", nil
}

func MaybeMakeDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("error creating %q: %v", dir, err)
		}
	} else if err != nil {
		return fmt.Errorf("error stat'ing %q: %v", dir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("%q already exists and it is not a dir", dir)
	}
	return nil
}

func Write(name string, data []byte) error {
	if err := MaybeMakeDir(filepath.Dir(name)); err != nil {
		return err
	}
	return ioutil.WriteFile(name, data, 0600)
}

func ExtractSeed(s string) (nkeys.KeyPair, error) {
	lines := strings.Split(s, "\n")
	start := -1
	end := -1
	for i, v := range lines {
		if strings.HasPrefix(v, "-----BEGIN ") && strings.HasSuffix(v, " SEED-----") {
			start = i + 1
			continue
		}
		if strings.HasPrefix(v, "------END ") && strings.HasSuffix(v, " SEED------") {
			end = i
			break
		}
	}

	if start != -1 && end != -1 {
		lines := lines[start:end]
		s = strings.Join(lines, "")
	}
	return nkeys.FromSeed([]byte(s))
}

func AbbrevHomePaths(fp string) string {
	h, err := homedir.Dir()
	if err != nil {
		return fp
	}
	if strings.HasPrefix(fp, h) {
		return strings.Replace(fp, h, "~", 1)
	}
	return fp
}
