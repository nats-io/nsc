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
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveLocal(t *testing.T) {
	old := os.Getenv(NkeysPathEnv)
	os.Setenv(NkeysPathEnv, "")

	dir := GetKeysDir()

	os.Setenv(NkeysPathEnv, old)

	u, err := user.Current()
	require.NoError(t, err)
	fp := filepath.Join(u.HomeDir, DefaultNkeysPath)

	require.Equal(t, dir, fp)
}

func TestResolveEnv(t *testing.T) {
	old := os.Getenv(NkeysPathEnv)

	p := filepath.Join("foo", "bar")
	os.Setenv(NkeysPathEnv, p)

	dir := GetKeysDir()

	os.Setenv(NkeysPathEnv, old)
	require.Equal(t, dir, p)
}

func TestResolveKeyEmpty(t *testing.T) {
	old := KeyPathFlag
	KeyPathFlag = ""

	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)
	require.Nil(t, rkp)
}

func TestResolveKeyFromSeed(t *testing.T) {
	seed, p, _ := CreateAccountKey(t)
	old := KeyPathFlag
	KeyPathFlag = string(seed)

	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)

	pp, err := rkp.PublicKey()
	require.NoError(t, err)

	require.Equal(t, string(pp), string(p))
}

func TestResolveKeyFromFile(t *testing.T) {
	dir := MakeTempDir(t)
	_, p, kp := CreateAccountKey(t)
	old := KeyPathFlag
	KeyPathFlag = StoreKey(t, kp, dir)
	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)

	pp, err := rkp.PublicKey()
	require.NoError(t, err)

	require.Equal(t, string(pp), string(p))
}

func TestResolveKeyFlagPrivateKey(t *testing.T) {
	dir := MakeTempDir(t)

	_, p, kp := CreateAccountKey(t)
	old := KeyPathFlag
	KeyPathFlag = StoreKey(t, kp, dir)

	fk, err := NewKeyStore().FindSeed(p)
	require.NoError(t, err)
	require.True(t, Match(p, fk))

	KeyPathFlag = old

}

func TestMatchKeys(t *testing.T) {
	_, apk, akp := CreateAccountKey(t)
	_, opk, _ := CreateOperatorKey(t)

	require.True(t, Match(apk, akp))
	require.False(t, Match(opk, akp))
}

func TestGetKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NkeysPathEnv)
	os.Setenv(NkeysPathEnv, dir)

	ks := NewKeyStore()

	_, apk, akp := CreateAccountKey(t)
	_, opk, okp := CreateOperatorKey(t)

	err := ks.Store("account", akp)
	require.NoError(t, err)

	err = ks.Store("operator", okp)
	require.NoError(t, err)

	keys, err := ks.GetAllKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)

	var pks []string
	for _, k := range keys {
		pk, err := k.PublicKey()
		require.NoError(t, err)
		pks = append(pks, string(pk))
	}
	require.ElementsMatch(t, pks, []string{apk, opk})

	os.Setenv(NkeysPathEnv, old)
}

func TestGetPrivateKey(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NkeysPathEnv)
	os.Setenv(NkeysPathEnv, dir)

	_, apk, akp := CreateAccountKey(t)
	_, opk, okp := CreateOperatorKey(t)
	_, cpk, _ := CreateClusterKey(t)

	ks := NewKeyStore()
	ks.Store("", akp)
	ks.Store("", okp)

	kp, err := ks.FindSeed(apk)
	require.NoError(t, err)
	require.NoError(t, err)
	require.True(t, Match(apk, kp))

	kp, err = ks.FindSeed(opk)
	require.NoError(t, err)
	require.NoError(t, err)
	require.True(t, Match(opk, okp))

	kp, err = ks.FindSeed(cpk)
	require.NoError(t, err)
	require.Nil(t, kp)

	os.Setenv(NkeysPathEnv, old)
}
