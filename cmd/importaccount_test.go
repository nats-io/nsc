/*
 * Copyright 2018-2022 The NATS Authors
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
	err = os.WriteFile(file, []byte(theJWT), 0666)
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
	test := func(force bool) {
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
		err = os.WriteFile(file, []byte(theJWT), 0666)
		require.NoError(t, err)
		if force {
			_, _, err = ExecuteCmd(createImportAccountCmd(), "--file", file, "--force")
			require.NoError(t, err)
		} else {
			_, _, err = ExecuteCmd(createImportAccountCmd(), "--file", file)
			require.Error(t, err)
		}
	}
	test(false)
	test(true)
}

func Test_ImportDecoratedAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	// save a naked jwt
	a, err := ts.Store.ReadRawAccountClaim("A")
	require.NoError(t, err)
	normal := filepath.Join(ts.Dir, "a.jwt")
	err = Write(normal, a)
	require.NoError(t, err)

	// save a decorated jwt
	decorated := filepath.Join(ts.Dir, "decorated_a.jwt")
	_, _, err = ExecuteCmd(rootCmd, "describe", "account", "A", "--raw", "--output-file", decorated)

	// delete the account
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createDeleteAccountCmd(), "A", "--force")
	require.NoError(t, err)
	_, err = ts.Store.ReadAccountClaim("A")
	require.Error(t, err)
	require.Equal(t, "account A does not exist in the current operator", err.Error())

	// import the naked jwt
	_, _, err = ExecuteCmd(rootCmd, "import", "account", "--file", normal)
	require.NoError(t, err)
	_, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createDeleteAccountCmd(), "A", "--force")
	require.NoError(t, err)

	// import the decorated jwt
	_, _, err = ExecuteCmd(rootCmd, "import", "account", "--file", decorated)
	require.NoError(t, err)
}
