// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func storeOldCreds(ts *TestStore, operator string, account string, user string, _data []byte) error {
	ks := filepath.Join(ts.Dir, "keys")
	target := filepath.Join(ks, operator, "accounts", account, "users", fmt.Sprintf("%s.creds", user))
	return os.WriteFile(target, []byte(user), 0700)

}

func storeOldKey(ts *TestStore, operator string, account string, user string, seed []byte) error {
	// old key layout was:
	// <op>/<op>.nk
	// <op>/accounts/<actname>/<actname>.nk
	// <op>/accounts/<actname>/users/<un>.creds
	// <op>/accounts/<actname>/users/<un>.nk
	// new key layout is:
	// keys/<op>/<first letter pk>/<second and third letters pk>/<pk>.nk
	// creds/<op>/<actname>/<un>.creds
	kp, err := store.ExtractSeed(string(seed))
	if err != nil {
		return err
	}
	prefix, err := store.KeyType(kp)
	if err != nil {
		return err
	}
	ks := filepath.Join(ts.Dir, "keys")
	var target string
	switch prefix {
	case nkeys.PrefixByteOperator:
		target = filepath.Join(ks, operator, fmt.Sprintf("%s.nk", operator))
	case nkeys.PrefixByteAccount:
		target = filepath.Join(ks, operator, "accounts", account, fmt.Sprintf("%s.nk", account))
	case nkeys.PrefixByteUser:
		target = filepath.Join(ks, operator, "accounts", account, "users", fmt.Sprintf("%s.nk", user))
	}

	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}

	return os.WriteFile(target, seed, 0700)
}

func Test_HasOldStructure(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	ks := filepath.Join(ts.Dir, "keys")
	old := store.KeyStorePath
	store.KeyStorePath = ks

	oseed, _, _ := CreateOperatorKey(t)
	require.NoError(t, storeOldKey(ts, "O", "", "", oseed))
	require.FileExists(t, filepath.Join(ks, "O", "O.nk"))

	aseed, _, _ := CreateAccountKey(t)
	require.NoError(t, storeOldKey(ts, "O", "A", "", aseed))
	require.FileExists(t, filepath.Join(ks, "O", "accounts", "A", "A.nk"))

	useed, _, _ := CreateUserKey(t)
	require.NoError(t, storeOldKey(ts, "O", "A", "U", useed))
	require.FileExists(t, filepath.Join(ks, "O", "accounts", "A", "users", "U.nk"))

	err := storeOldCreds(ts, "O", "A", "U", []byte("user"))
	require.NoError(t, err)

	isOld, err := store.IsOldKeyRing(store.GetKeysDir())
	require.NoError(t, err)
	require.True(t, isOld)
	store.KeyStorePath = old
}

func Test_NoMigration(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	out, err := ExecuteCmd(createMigrateKeysCmd())
	require.NoError(t, err)
	require.Contains(t, out.Out, "does not need migration")
}

func Test_MigrateKeys(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	ks := filepath.Join(ts.Dir, "keys")
	oldKs := store.KeyStorePath
	store.KeyStorePath = ks

	oseed, opk, _ := CreateOperatorKey(t)
	require.NoError(t, storeOldKey(ts, "O", "", "", oseed))
	require.FileExists(t, filepath.Join(ks, "O", "O.nk"))

	aseed, apk, _ := CreateAccountKey(t)
	require.NoError(t, storeOldKey(ts, "O", "A", "", aseed))
	require.FileExists(t, filepath.Join(ks, "O", "accounts", "A", "A.nk"))

	useed, upk, _ := CreateUserKey(t)
	require.NoError(t, storeOldKey(ts, "O", "A", "U", useed))
	require.FileExists(t, filepath.Join(ks, "O", "accounts", "A", "users", "U.nk"))

	err := storeOldCreds(ts, "O", "A", "U", []byte("user"))
	require.NoError(t, err)

	needsUpdate, err := store.KeysNeedMigration()
	require.NoError(t, err)
	require.True(t, needsUpdate)

	_, err = ExecuteCmd(createMigrateKeysCmd(), []string{}...)
	require.NoError(t, err)

	// directory for keystore has a "keys" and "creds"
	keysDir := filepath.Join(ks, "keys")
	require.FileExists(t, filepath.Join(keysDir, "O", opk[1:3], fmt.Sprintf("%s.nk", opk)))
	require.FileExists(t, filepath.Join(keysDir, "A", apk[1:3], fmt.Sprintf("%s.nk", apk)))
	require.FileExists(t, filepath.Join(keysDir, "U", upk[1:3], fmt.Sprintf("%s.nk", upk)))

	credsDir := filepath.Join(ks, "creds")
	cf := filepath.Join(credsDir, "O", "A", "U.creds")
	require.FileExists(t, cf)

	for _, pk := range []string{opk, apk, upk} {
		kp, err := ts.KeyStore.GetKeyPair(pk)
		require.NoError(t, err)
		require.NotNil(t, kp)
	}
	store.KeyStorePath = oldKs
}
