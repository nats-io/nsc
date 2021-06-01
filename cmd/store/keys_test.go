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
	"os"
	"path/filepath"
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func TestResolveLocal(t *testing.T) {
	old := os.Getenv(NKeysPathEnv)
	require.NoError(t, os.Setenv(NKeysPathEnv, ""))

	dir := GetKeysDir()

	require.NoError(t, os.Setenv(NKeysPathEnv, old))

	u, err := homedir.Dir()
	require.NoError(t, err)
	fp := filepath.Join(u, DefaultNKeysPath)

	require.Equal(t, dir, fp)
}

func TestResolveEnv(t *testing.T) {
	old := os.Getenv(NKeysPathEnv)

	p := filepath.Join("foo", "bar")
	require.NoError(t, os.Setenv(NKeysPathEnv, p))

	dir := GetKeysDir()

	require.NoError(t, os.Setenv(NKeysPathEnv, old))
	require.Equal(t, dir, p)
}

func TestMatchKeys(t *testing.T) {
	_, apk, akp := CreateAccountKey(t)
	_, opk, _ := CreateOperatorKey(t)

	require.True(t, Match(apk, akp))
	require.False(t, Match(opk, akp))
}

func TestGetKeyNonExist(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NKeysPathEnv)
	require.NoError(t, os.Setenv(NKeysPathEnv, dir))

	ks := NewKeyStore("test_get_keys")
	_, _, okp := CreateOperatorKey(t)
	_, err := ks.Store(okp)
	require.NoError(t, err)

	_, apk, _ := CreateAccountKey(t)
	kp, err := ks.GetKeyPair(apk)
	require.NoError(t, err)
	require.Nil(t, kp)

	require.NoError(t, os.Setenv(NKeysPathEnv, old))
}

func TestGetKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NKeysPathEnv)
	require.NoError(t, os.Setenv(NKeysPathEnv, dir))

	ks := NewKeyStore("test_get_keys")

	_, opk, okp := CreateOperatorKey(t)

	_, err := ks.Store(okp)
	require.NoError(t, err)
	ookp, err := ks.GetKeyPair(opk)
	require.NoError(t, err)
	oopk, err := ookp.PublicKey()
	require.NoError(t, err)
	require.True(t, Match(opk, ookp))
	require.Equal(t, opk, oopk)

	_, apk, akp := CreateAccountKey(t)
	_, err = ks.Store(akp)
	require.NoError(t, err)

	aakp, err := ks.GetKeyPair(apk)
	require.NoError(t, err)

	aapk, err := aakp.PublicKey()
	require.NoError(t, err)

	require.True(t, Match(apk, aakp))
	require.Equal(t, apk, aapk)

	require.NoError(t, os.Setenv(NKeysPathEnv, old))
}

func Test_RemoveKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NKeysPathEnv)
	require.NoError(t, os.Setenv(NKeysPathEnv, dir))

	ks := NewKeyStore(t.Name())

	_, opk, okp := CreateOperatorKey(t)

	_, err := ks.Store(okp)
	require.NoError(t, err)
	ookp, err := ks.GetKeyPair(opk)
	require.NoError(t, err)
	oopk, err := ookp.PublicKey()
	require.NoError(t, err)
	require.True(t, Match(opk, ookp))
	require.Equal(t, opk, oopk)

	require.NoError(t, ks.Remove(opk))
	kp := ks.GetKeyPath(opk)
	_, err = os.Stat(kp)
	require.True(t, os.IsNotExist(err))

	require.NoError(t, os.Setenv(NKeysPathEnv, old))
}

func TestGetMissingKey(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NKeysPathEnv)
	require.NoError(t, os.Setenv(NKeysPathEnv, dir))

	_, opk, _ := CreateOperatorKey(t)

	ks := NewKeyStore("test_get_private_key")

	ckp, err := ks.GetKeyPair(opk)
	require.Nil(t, err)
	require.Nil(t, ckp)
	_ = os.Setenv(NKeysPathEnv, old)
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

	return seed, pub, kp
}

func TestAllKeys(t *testing.T) {
	dir := MakeTempDir(t)
	old := os.Getenv(NKeysPathEnv)
	require.NoError(t, os.Setenv(NKeysPathEnv, dir))
	defer func() {
		_ = os.Setenv(NKeysPathEnv, old)
	}()

	ks := NewKeyStore(t.Name())
	_, opk, okp := CreateOperatorKey(t)
	_, err := ks.Store(okp)
	require.NoError(t, err)

	_, apk, akp := CreateAccountKey(t)
	_, err = ks.Store(akp)
	require.NoError(t, err)

	keys, err := ks.AllKeys()
	require.NoError(t, err)
	require.Contains(t, keys, opk)
	require.Contains(t, keys, apk)
}
