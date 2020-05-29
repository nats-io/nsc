/*
 * Copyright 2018-2020 The NATS Authors
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

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nuid"
)

var NscNotGitIgnore bool

const DefaultNKeysPath = ".nkeys"
const NKeysPathEnv = "NKEYS_PATH"
const NKeyExtension = ".nk"
const CredsExtension = ".creds"
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
	return ResolvePath(filepath.Join(u.HomeDir, DefaultNKeysPath), NKeysPathEnv)
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

func IsOldKeyRing(dir string) (bool, error) {
	var err error
	dir, err = homedir.Expand(dir)
	if err != nil {
		return false, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	isOld := false
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info == nil && err != nil {
			return err
		}
		// breakout if we determined we have old keyring
		if isOld {
			return filepath.SkipDir
		}
		// make the path relative to ease parsing
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		// this is the keys/creds dir - ignore them
		if (rel == KeysDir || rel == CredsDir) && info.IsDir() {
			// walking new dirs
			return filepath.SkipDir
		}
		// if we find a key/creds file outside of the expected place
		// we have the old structure
		ext := filepath.Ext(path)
		if ext == NKeyExtension || ext == CredsExtension {
			isOld = true
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil && err != filepath.SkipDir {
		return false, err
	}
	return isOld, nil
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
	return IsOldKeyRing(dir)
}

func Migrate() (string, error) {
	dir := GetKeysDir()
	// make a new directory next to it
	name := nuid.Next()
	to := filepath.Join(filepath.Dir(dir), name)

	if err := makeKeyStore(to); err != nil {
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

func (k *KeyStore) AllKeys() ([]string, error) {
	var keys []string
	err := filepath.Walk(GetKeysDir(), func(src string, info os.FileInfo, err error) error {
		ext := filepath.Ext(src)
		switch ext {
		case NKeyExtension:
			n := filepath.Base(src)
			keys = append(keys, n[:len(n)-3])
		}
		return nil
	})
	return keys, err
}

func (k *KeyStore) credsName(n string) string {
	return fmt.Sprintf("%s%s", n, CredsExtension)
}

func (k *KeyStore) CalcAccountCredsDir(account string) string {
	return filepath.Join(GetKeysDir(), CredsDir, k.Env, account)
}

func (k *KeyStore) CalcUserCredsPath(account string, user string) string {
	return filepath.Join(GetKeysDir(), CredsDir, k.Env, account, k.credsName(user))
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

	return fp, ioutil.WriteFile(fp, data, 0600)
}

func (k *KeyStore) keypath(kp nkeys.KeyPair) (string, error) {
	pk, err := kp.PublicKey()
	if err != nil {
		return "", err
	}
	return k.GetKeyPath(pk), nil
}

func makeKeyStore(dir string) error {
	if err := MaybeMakeDir(filepath.Join(dir, KeysDir)); err != nil {
		return err
	}
	if err := MaybeMakeDir(filepath.Join(dir, CredsDir)); err != nil {
		return err
	}
	if err := AddGitIgnore(dir); err != nil {
		return err
	}
	return nil
}

func (k *KeyStore) GetKeyPath(pubkey string) string {
	if pubkey == "" {
		return ""
	}
	kind := pubkey[0:1]
	shard := pubkey[1:3]
	return filepath.Join(GetKeysDir(), KeysDir, kind, shard, fmt.Sprintf("%s%s", pubkey, NKeyExtension))
}

func (k *KeyStore) GetKeyPair(pubkey string) (nkeys.KeyPair, error) {
	return k.Read(k.GetKeyPath(pubkey))
}

func (k *KeyStore) GetPublicKey(pubkey string) (string, error) {
	return k.getPublicKey(k.GetKeyPair(pubkey))
}

func (k *KeyStore) HasPrivateKey(pubkey string) bool {
	kp, err := k.GetKeyPair(pubkey)
	if kp == nil || err != nil {
		return false
	}
	_, err = kp.Seed()
	return err == nil
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

func (k *KeyStore) Remove(pubkey string) error {
	kp := k.GetKeyPath(pubkey)
	_, err := os.Stat(kp)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.Remove(kp); err != nil {
		return err
	}
	pd := filepath.Dir(kp)
	infos, err := ioutil.ReadDir(pd)
	// nothing to do from here, but attempt to cleanup
	// empty directories - go won't delete empty dirs
	// but we check anyway
	if err == nil && len(infos) == 0 {
		os.Remove(pd)
	}
	return nil
}

func AddGitIgnore(dir string) error {
	if NscNotGitIgnore {
		return nil
	}
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

func (k *KeyStore) Store(kp nkeys.KeyPair) (string, error) {
	if err := makeKeyStore(GetKeysDir()); err != nil {
		return "", err
	}
	fp, err := k.keypath(kp)
	if err != nil {
		return "", err
	}

	seed, err := kp.Seed()
	if err != nil {
		return "", fmt.Errorf("error reading seed from nkey: %v", err)
	}

	if err := MaybeMakeDir(filepath.Dir(fp)); err != nil {
		return "", err
	}

	_, err = os.Stat(fp)
	if err != nil {
		if os.IsNotExist(err) {
			err := ioutil.WriteFile(fp, seed, 0600)
			if err != nil {
				return "", fmt.Errorf("error writing %#q: %v", fp, err)
			}
			return fp, nil
		}
	}

	d, err := ioutil.ReadFile(fp)
	if err != nil {
		return "", fmt.Errorf("error reading %#q: %v", fp, err)
	}
	if string(d) != string(seed) {
		return "", fmt.Errorf("key %#q already exists and is different", fp)
	}
	return fp, err
}

func (k *KeyStore) Read(path string) (nkeys.KeyPair, error) {
	return keyFromFile(path)
}

func Match(pubkey string, kp nkeys.KeyPair) bool {
	pk, err := kp.PublicKey()
	if err != nil {
		return false
	}
	if pubkey != pk {
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
	var err error

	// value could be a ~/ expand it
	path, err = homedir.Expand(path)
	if err != nil {
		return nil, err
	}
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

func PubKeyType(pk string) (nkeys.PrefixByte, error) {
	if nkeys.IsValidPublicOperatorKey(pk) {
		return nkeys.PrefixByteOperator, nil
	}
	if nkeys.IsValidPublicAccountKey(pk) {
		return nkeys.PrefixByteAccount, nil
	}
	if nkeys.IsValidPublicClusterKey(pk) {
		return nkeys.PrefixByteCluster, nil
	}
	if nkeys.IsValidPublicServerKey(pk) {
		return nkeys.PrefixByteServer, nil
	}
	if nkeys.IsValidPublicUserKey(pk) {
		return nkeys.PrefixByteUser, nil
	}
	return 0, fmt.Errorf("unsupported key type")
}

func KeyType(kp nkeys.KeyPair) (nkeys.PrefixByte, error) {
	pk, err := kp.PublicKey()
	if err != nil {
		return 0, err
	}
	return PubKeyType(pk)
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
		return false, fmt.Errorf("%#q is not a directory", fp)
	}
}

func migrateKeyStore(ksroot string, to string) (keys []string, creds []string, err error) {
	if err := MaybeMakeDir(to); err != nil {
		return nil, nil, err
	}
	if err := MaybeMakeDir(filepath.Join(to, "keys")); err != nil {
		return nil, nil, err
	}
	if err := MaybeMakeDir(filepath.Join(to, "creds")); err != nil {
		return nil, nil, err
	}

	err = filepath.Walk(ksroot, func(src string, info os.FileInfo, err error) error {
		ext := filepath.Ext(src)
		switch ext {
		case NKeyExtension:
			fp, err := migrateKey(src, to)
			if err != nil {
				return err
			}
			if fp == "" {
				return nil
			}
			keys = append(keys, fp)
		case CredsExtension:
			fp, err := migrateCreds(ksroot, src, to)
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
	if filepath.Ext(src) == NKeyExtension {
		d, err := dataFromFile(src)
		if err != nil {
			return "", fmt.Errorf("error processing %#q: %v", src, err)
		}
		kp, err := nkeys.FromSeed(d)
		if err != nil {
			return "", fmt.Errorf("error processing %#q: %v", src, err)
		}

		pk, err := kp.PublicKey()
		if err != nil {
			return "", fmt.Errorf("error processing %#q: %v", src, err)
		}
		kind := pk[0:1]
		shard := pk[1:3]

		fp := filepath.Join(to, "keys", kind, shard, fmt.Sprintf("%s%s", pk, NKeyExtension))
		if err := MaybeMakeDir(filepath.Dir(fp)); err != nil {
			return "", err
		}
		return fp, Write(fp, d)
	}
	return "", nil
}

func relCredsPath(ksroot string, p string) (string, error) {
	// old creds are expected as:
	// <op>/accounts/<actname>/users/<un>.creds
	// new creds are found:
	// creds/<op>/<actname>/<un>.creds
	rel, err := filepath.Rel(ksroot, p)
	if err != nil {
		return "", err
	}
	a := strings.Split(rel, string(os.PathSeparator))
	if len(a) == 4 && a[0] == CredsDir {
		// this is a file in the current format
		return rel, nil
	}
	if len(a) == 5 {
		return filepath.Join(CredsDir, a[0], a[2], a[4]), nil
	}
	return "", fmt.Errorf("unexpected creds filepath len of %d: %#q", len(a), rel)

}

func migrateCreds(ksroot string, src string, to string) (string, error) {
	if filepath.Ext(src) == CredsExtension {
		d, err := dataFromFile(src)
		if err != nil {
			return "", fmt.Errorf("error processing %#q: %v", src, err)
		}

		rel, err := relCredsPath(ksroot, src)
		if err != nil {
			return "", err
		}

		to := filepath.Join(to, rel)
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
			return fmt.Errorf("error creating %#q: %v", dir, err)
		}
	} else if err != nil {
		return fmt.Errorf("error stat'ing %#q: %v", dir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("%#q already exists and it is not a dir", dir)
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
