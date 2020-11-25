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
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	jwtv2 "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func Test_ImportAccountSelfSigned(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	akp, _ := nkeys.CreateAccount()
	pk, _ := akp.PublicKey()
	ac := jwt.NewAccountClaims(pk)
	ac.Name = ac.Subject
	theJWT, err := ac.Encode(akp)
	require.NoError(t, err)
	require.True(t, ac.IsSelfSigned())

	check := func() {
		t.Helper()
		claim, err := ts.Store.ReadAccountClaim(pk)
		require.NoError(t, err)
		require.False(t, claim.IsSelfSigned())
	}

	file := filepath.Join(ts.Dir, "account-selfsigned.jwt")
	err = ioutil.WriteFile(file, []byte(theJWT), 0666)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createImportAccountCmd(), "--file", file)
	require.NoError(t, err)
	check()
	_, _, err = ExecuteCmd(createImportAccountCmd(), "--file", file)
	require.Error(t, err)
	_, _, err = ExecuteCmd(createImportAccountCmd(), "--file", file, "--overwrite")
	require.NoError(t, err)
	check()
}

func Test_ImportAccountOtherOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	oKp, _ := nkeys.CreateOperator()
	akp, _ := nkeys.CreateAccount()
	pk, _ := akp.PublicKey()
	ac := jwt.NewAccountClaims(pk)
	ac.Name = ac.Subject
	theJWT, err := ac.Encode(oKp)
	require.NoError(t, err)
	require.False(t, ac.IsSelfSigned())
	file := filepath.Join(ts.Dir, "account.jwt")
	err = ioutil.WriteFile(file, []byte(theJWT), 0666)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createImportAccountCmd(), "--file", file)
	require.Error(t, err)
}

func Test_ImportAccountV2(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	aKp, _ := nkeys.CreateAccount()
	pk, _ := aKp.PublicKey()
	acp := jwtv2.NewAccountClaims(pk)
	theJWT, err := acp.Encode(aKp) // this account being self signed does not matter for this test
	require.NoError(t, err)
	file := filepath.Join(ts.Dir, "account.jwt")
	err = ioutil.WriteFile(file, []byte(theJWT), 0666)
	require.NoError(t, err)
	_, stdErr, err := ExecuteCmd(createImportAccountCmd(), "--file", file)
	require.Error(t, err)
	require.Contains(t, stdErr, JWTUpgradeBannerJWT())
}
