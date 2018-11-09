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
	"strings"

	"github.com/nats-io/nkeys"
)

var KeyPathFromFlag string

const DefaultNkeysDir = "~/.nkeys"

func GetKeysDir() string {
	return ResolveKeysDir(DefaultNkeysDir)
}

func ResolveKeysDir(defaultDir string) string {
	v := os.Getenv(NkeysDirEnv)
	if v != "" {
		return v
	}
	return defaultDir
}

func ResolveKeyFlag() (nkeys.KeyPair, error) {
	if KeyPathFromFlag != "" {
		kp, err := resolveKey(KeyPathFromFlag)
		if err != nil {
			return nil, err
		}
		return kp, nil
	}
	return nil, nil
}

func MatchKeys(pubkey string, kp nkeys.KeyPair) (bool, error) {
	pk, err := kp.PublicKey()
	if err != nil {
		return false, err
	}
	if pubkey != string(pk) {
		return false, nil
	}

	return true, nil
}

func GetKeys() ([]nkeys.KeyPair, error) {
	dir := GetKeysDir()
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

func GetPrivateKey(pubkey string) (nkeys.KeyPair, error) {
	// use of flag overrides anything
	kp, err := ResolveKeyFlag()
	if err != nil {
		return nil, err
	}
	if kp != nil {
		ok, err := MatchKeys(pubkey, kp)
		if err != nil {
			return nil, err
		}
		if ok {
			return kp, nil
		} else {
			return nil, nil
		}
	}

	keys, err := GetKeys()
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		ok, err := MatchKeys(pubkey, k)
		if err != nil {
			return nil, err
		}
		if ok {
			return k, nil
		}
	}
	return nil, nil
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
