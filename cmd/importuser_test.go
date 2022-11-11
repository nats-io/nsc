/*
 * Copyright 2020-2020 The NATS Authors
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
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func Test_ImportUserCreds(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "acc")
	require.NoError(t, err)
	aClaim, _ := ts.Store.ReadAccountClaim("acc")
	aKp, err := ts.KeyStore.GetKeyPair(aClaim.Subject)
	require.NoError(t, err)

	uKp, _ := nkeys.CreateUser()
	pk, _ := uKp.PublicKey()
	uc := jwt.NewUserClaims(pk)
	uc.Name = uc.Subject
	theJWT, err := uc.Encode(aKp)
	require.NoError(t, err)
	require.False(t, ts.KeyStore.HasPrivateKey(pk))

	check := func() {
		t.Helper()
		_, err := ts.Store.ReadUserClaim("acc", pk)
		require.NoError(t, err)
		require.True(t, ts.KeyStore.HasPrivateKey(pk))
	}

	seed, err := uKp.Seed()
	require.NoError(t, err)
	creds, err := jwt.FormatUserConfig(theJWT, seed)
	require.NoError(t, err)

	file := filepath.Join(ts.Dir, "user.creds")
	err = os.WriteFile(file, creds, 0666)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createImportUserCmd(), "--file", file)
	require.NoError(t, err)
	check()
	_, _, err = ExecuteCmd(createImportUserCmd(), "--file", file)
	require.Error(t, err)
	_, _, err = ExecuteCmd(createImportUserCmd(), "--file", file, "--overwrite")
	require.NoError(t, err)
	check()
}

func Test_ImportUserJWT(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "acc")
	require.NoError(t, err)

	aClaim, _ := ts.Store.ReadAccountClaim("acc")
	aKp, err := ts.KeyStore.GetKeyPair(aClaim.Subject)
	require.NoError(t, err)

	uKp, _ := nkeys.CreateUser()
	pk, _ := uKp.PublicKey()
	uc := jwt.NewUserClaims(pk)
	uc.Name = uc.Subject
	theJWT, err := uc.Encode(aKp)
	require.NoError(t, err)

	check := func() {
		t.Helper()
		_, err := ts.Store.ReadUserClaim("acc", pk)
		require.NoError(t, err)
	}

	file := filepath.Join(ts.Dir, "user.jwt")
	err = os.WriteFile(file, []byte(theJWT), 0666)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createImportUserCmd(), "--file", file)
	require.NoError(t, err)
	check()
	_, _, err = ExecuteCmd(createImportUserCmd(), "--file", file)
	require.Error(t, err)
	_, _, err = ExecuteCmd(createImportUserCmd(), "--file", file, "--overwrite")
	require.NoError(t, err)
	check()
}

func Test_ImportUserOtherAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	aKp, _ := nkeys.CreateAccount()
	uKp, _ := nkeys.CreateUser()
	pk, _ := uKp.PublicKey()
	uc := jwt.NewUserClaims(pk)
	uc.Name = uc.Subject
	theJWT, err := uc.Encode(aKp)
	require.NoError(t, err)
	file := filepath.Join(ts.Dir, "user.jwt")
	err = os.WriteFile(file, []byte(theJWT), 0666)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createImportUserCmd(), "--file", file)
	require.Error(t, err)
}
