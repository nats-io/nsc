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
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func TestResolveLocal(t *testing.T) {
	old := os.Getenv(NkeysDirEnv)
	os.Setenv(NkeysDirEnv, "")

	dir := GetKeysDir()

	os.Setenv(NkeysDirEnv, old)

	u, err := user.Current()
	require.NoError(t, err)
	fp := filepath.Join(u.HomeDir, DefaultNkeysDirName)

	require.Equal(t, dir, fp)
}

func TestResolveEnv(t *testing.T) {
	old := os.Getenv(NkeysDirEnv)

	p := filepath.Join("foo", "bar")
	os.Setenv(NkeysDirEnv, p)

	dir := GetKeysDir()

	os.Setenv(NkeysDirEnv, old)
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

	fk, err := GetPrivateKey(p)
	require.NoError(t, err)
	ok, err := MatchKeys(p, fk)
	require.NoError(t, err)
	require.True(t, ok)

	KeyPathFlag = old
}

func TestMatchKeys(t *testing.T) {
	_, apk, akp := CreateAccountKey(t)
	_, opk, _ := CreateOperatorKey(t)

	ok, err := MatchKeys(apk, akp)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = MatchKeys(opk, akp)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestGetKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NkeysDirEnv)
	os.Setenv(NkeysDirEnv, dir)

	_, apk, akp := CreateAccountKey(t)
	_, opk, okp := CreateOperatorKey(t)

	StoreKey(t, akp, dir)
	StoreKey(t, okp, dir)

	keys, err := GetKeys()
	require.NoError(t, err)
	require.Len(t, keys, 2)

	var pks []string
	for _, k := range keys {
		pk, err := k.PublicKey()
		require.NoError(t, err)
		pks = append(pks, string(pk))
	}
	require.ElementsMatch(t, pks, []string{apk, opk})

	os.Setenv(NkeysDirEnv, old)
}

func TestGetPrivateKey(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NkeysDirEnv)
	os.Setenv(NkeysDirEnv, dir)

	_, apk, akp := CreateAccountKey(t)
	_, opk, okp := CreateOperatorKey(t)
	_, cpk, _ := CreateClusterKey(t)

	StoreKey(t, akp, dir)
	StoreKey(t, okp, dir)

	kp, err := GetPrivateKey(apk)
	require.NoError(t, err)
	ok, err := MatchKeys(apk, kp)
	require.NoError(t, err)
	require.True(t, ok)

	kp, err = GetPrivateKey(opk)
	require.NoError(t, err)
	ok, err = MatchKeys(opk, okp)
	require.NoError(t, err)
	require.True(t, ok)

	kp, err = GetPrivateKey(cpk)
	require.NoError(t, err)
	require.Nil(t, kp)

	os.Setenv(NkeysDirEnv, old)
}

func MakeTempDir(t *testing.T) string {
	p, err := ioutil.TempDir("", "store_test")
	require.NoError(t, err)
	return p
}

func StoreKey(t *testing.T, kp nkeys.KeyPair, dir string) string {
	p, err := kp.PublicKey()
	require.NoError(t, err)

	s, err := kp.Seed()
	require.NoError(t, err)

	fp := filepath.Join(dir, string(p)+".nk")
	err = ioutil.WriteFile(fp, s, 0600)
	require.NoError(t, err)
	return fp
}

func CreateClusterKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateCluster)
}

func CreateAccountKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateAccount)
}

func CreateOperatorKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateOperator)
}

type NKeyFactory func() (nkeys.KeyPair, error)

func CreateNkey(t *testing.T, f NKeyFactory) ([]byte, string, nkeys.KeyPair) {
	kp, err := f()
	require.NoError(t, err)

	seed, err := kp.Seed()
	require.NoError(t, err)

	pub, err := kp.PublicKey()
	require.NoError(t, err)

	return seed, string(pub), kp
}
