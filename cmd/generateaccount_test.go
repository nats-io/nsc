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
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestGenerateAccount(t *testing.T) {
	dir := MakeTempDir(t)

	os.Setenv(store.DataHomeEnv, dir)
	InitStore(t)

	tests := CmdTests{
		{createGenerateAccountCmd(), []string{"export", "account"}, []string{"BEGIN ACCOUNT JWT", "END ACCOUNT JWT"}, nil, false},
	}
	tests.Run(t, "root", "export")

}

func TestGenerateAccountExpiration(t *testing.T) {
	dir := MakeTempDir(t)

	os.Setenv(store.DataHomeEnv, dir)
	InitStore(t)

	fn := filepath.Join(dir, "output.jwt")
	_, _, err := ExecuteCmd(createGenerateAccountCmd(), "-e", "2d", "-o", fn)
	require.NoError(t, err)

	exp := time.Now().AddDate(0, 0, 2)

	require.FileExists(t, fn)
	d, err := ioutil.ReadFile(fn)
	require.NoError(t, err)

	token := ExtractToken(string(d))
	ac, err := jwt.DecodeAccountClaims(token)
	require.NoError(t, err)

	exp2 := time.Unix(ac.Expires, 0)
	require.WithinDuration(t, exp, exp2, time.Second*5)
}

func TestGenerateAccountDefaultExpiration(t *testing.T) {
	dir := MakeTempDir(t)

	os.Setenv(store.DataHomeEnv, dir)
	InitStore(t)

	fn := filepath.Join(dir, "output.jwt")

	exp := time.Now().AddDate(0, 0, 30).Unix()
	_, _, err := ExecuteCmd(createGenerateAccountCmd(), "-o", fn)
	require.NoError(t, err)

	require.FileExists(t, fn)
	d, err := ioutil.ReadFile(fn)
	require.NoError(t, err)

	token := ExtractToken(string(d))
	ac, err := jwt.DecodeAccountClaims(token)
	require.NoError(t, err)
	require.InDelta(t, exp, ac.Expires, .999, "expiration")
}

func TestGenerateAccountNoExpiration(t *testing.T) {
	dir := MakeTempDir(t)

	os.Setenv(store.DataHomeEnv, dir)
	InitStore(t)

	fn := filepath.Join(dir, "output.jwt")

	_, _, err := ExecuteCmd(createGenerateAccountCmd(), "-e", "0", "-o", fn)
	require.NoError(t, err)

	require.FileExists(t, fn)
	d, err := ioutil.ReadFile(fn)
	require.NoError(t, err)

	token := ExtractToken(string(d))
	ac, err := jwt.DecodeAccountClaims(token)
	require.NoError(t, err)
	require.Zero(t, ac.Expires)
}

func TestGenerateAccountNoActivation(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	s, _ := InitStore(t)
	os.Remove(filepath.Join(s.Dir, s.Profile, store.AccountActivation))

	_, _, err := ExecuteCmd(createGenerateAccountCmd())
	require.NoError(t, err)
}

func TestGenerateAccountExpiredActivation(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	s, _ := InitStore(t)
	pk, err := s.GetPublicKey()
	require.NoError(t, err)

	fn := filepath.Join(s.Dir, s.Profile, store.AccountActivation)
	os.Remove(fn)
	d := CreateExpiringActivation(t, pk, nil)
	ioutil.WriteFile(fn, []byte(d), 0644)
	time.Sleep(time.Millisecond * 1500)

	_, stderr, err := ExecuteCmd(createGenerateAccountCmd())
	require.Error(t, err)
	require.Contains(t, stderr, "claim is expired")
}
