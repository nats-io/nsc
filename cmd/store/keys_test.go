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
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/stretchr/testify/require"
)

func TestResolveLocal(t *testing.T) {
	old := os.Getenv(NKeysPathEnv)
	os.Setenv(NKeysPathEnv, "")

	dir := GetKeysDir()

	os.Setenv(NKeysPathEnv, old)

	u, err := user.Current()
	require.NoError(t, err)
	fp := filepath.Join(u.HomeDir, DEfaultNKeysPath)

	require.Equal(t, dir, fp)
}

func TestResolveEnv(t *testing.T) {
	old := os.Getenv(NKeysPathEnv)

	p := filepath.Join("foo", "bar")
	os.Setenv(NKeysPathEnv, p)

	dir := GetKeysDir()

	os.Setenv(NKeysPathEnv, old)
	require.Equal(t, dir, p)
}

func TestMatchKeys(t *testing.T) {
	_, apk, akp := CreateAccountKey(t)
	_, opk, _ := CreateOperatorKey(t)

	require.True(t, Match(apk, akp))
	require.False(t, Match(opk, akp))
}

func TestGetKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NKeysPathEnv)
	os.Setenv(NKeysPathEnv, dir)

	ks := NewKeyStore("test_get_keys")

	_, opk, okp := CreateOperatorKey(t)
	_, apk, akp := CreateAccountKey(t)

	_, err := ks.Store("operator", okp, "operator")
	require.NoError(t, err)

	_, err = ks.Store("account", akp, "operator")
	require.NoError(t, err)

	ookp, err := ks.GetOperatorKey("operator")
	require.NoError(t, err)

	aakp, err := ks.GetAccountKey("operator", "account")
	require.NoError(t, err)

	require.True(t, Match(opk, ookp))
	require.True(t, Match(apk, aakp))

	os.Setenv(NKeysPathEnv, old)
}

func TestGetPrivateKey(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NKeysPathEnv)
	os.Setenv(NKeysPathEnv, dir)

	_, _, okp := CreateOperatorKey(t)
	_, _, akp := CreateAccountKey(t)

	ks := NewKeyStore("test_get_private_key")
	ks.Store("o", okp, "o")
	ks.Store("a", akp, "o")
	ckp, err := ks.GetClusterKey("o", "c")
	require.Error(t, err)
	require.Nil(t, ckp)

	os.Setenv(NKeysPathEnv, old)
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
	return CreateTestNKey(t, nkeys.CreateCluster)
}

func CreateAccountKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateAccount)
}

func CreateOperatorKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateOperator)
}

func CreateUserKey(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateTestNKey(t, nkeys.CreateUser)
}

func CreateTestNKey(t *testing.T, f NKeyFactory) ([]byte, string, nkeys.KeyPair) {
	kp, err := f()
	require.NoError(t, err)

	seed, err := kp.Seed()
	require.NoError(t, err)

	pub, err := kp.PublicKey()
	require.NoError(t, err)

	return seed, string(pub), kp
}
