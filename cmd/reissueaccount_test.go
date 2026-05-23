// Copyright 2020-2025 The NATS Authors
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
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_ReissueAccountPreflightNoForce(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	ac1, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	oldSubject := ac1.Subject

	// without --force, should report and stop
	out, err := ExecuteCmd(createReissueAccountCmd(), "--account", "A")
	require.NoError(t, err)
	require.Contains(t, out.Out, "re-run with --force")

	// account should not have changed
	ac2, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, oldSubject, ac2.Subject)
}

func Test_ReissueAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac1, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	oldSubject := ac1.Subject

	_, err = ExecuteCmd(createReissueAccountCmd(), "--account", "A", "--force")
	require.NoError(t, err)

	ac2, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotEqual(t, oldSubject, ac2.Subject)
}

func Test_ReissueAccountUsersResigned(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	ac1, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	oldSubject := ac1.Subject

	uc1, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, oldSubject, uc1.Issuer)

	_, err = ExecuteCmd(createReissueAccountCmd(), "--account", "A", "--force")
	require.NoError(t, err)

	ac2, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotEqual(t, oldSubject, ac2.Subject)

	// user must be re-signed by the new account identity
	uc2, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, ac2.Subject, uc2.Issuer)
	require.Empty(t, uc2.IssuerAccount)
}

func Test_ReissueAccountPublicImportUpdated(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	// account A exports a public stream
	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, true)
	// account B imports from A
	ts.AddAccount(t, "B")
	ts.AddImport(t, "A", jwt.Stream, "foo.>", "B")

	ac1, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	oldSubject := ac1.Subject

	bc1, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, bc1.Imports, 1)
	require.Equal(t, oldSubject, bc1.Imports[0].Account)

	// reissue A
	_, err = ExecuteCmd(createReissueAccountCmd(), "--account", "A", "--force")
	require.NoError(t, err)

	ac2, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotEqual(t, oldSubject, ac2.Subject)

	// B's import should now reference new subject
	bc2, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, bc2.Imports, 1)
	require.Equal(t, ac2.Subject, bc2.Imports[0].Account)
}

func Test_ReissueAccountPrivateImportTokenUpdated(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	// account A exports a private stream
	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, false)
	// account B imports from A with activation token
	ts.AddAccount(t, "B")
	ts.AddImport(t, "A", jwt.Stream, "foo.>", "B")

	ac1, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	oldSubject := ac1.Subject

	bc1, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, bc1.Imports, 1)
	require.NotEmpty(t, bc1.Imports[0].Token)
	require.Equal(t, oldSubject, bc1.Imports[0].Account)

	act1, err := jwt.DecodeActivationClaims(bc1.Imports[0].Token)
	require.NoError(t, err)
	require.Equal(t, oldSubject, act1.Issuer)

	// reissue A
	_, err = ExecuteCmd(createReissueAccountCmd(), "--account", "A", "--force")
	require.NoError(t, err)

	ac2, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotEqual(t, oldSubject, ac2.Subject)

	// B's import should be updated
	bc2, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, bc2.Imports, 1)
	require.Equal(t, ac2.Subject, bc2.Imports[0].Account)

	// activation token should be re-signed
	act2, err := jwt.DecodeActivationClaims(bc2.Imports[0].Token)
	require.NoError(t, err)
	require.NotEqual(t, oldSubject, act2.Issuer)
}

func Test_ReissueAccountUserWithScopedSigningKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	// add a scoped signing key to the account
	_, skPub, skKP := CreateAccountKey(t)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	scope := jwt.NewUserScope()
	scope.Key = skPub
	scope.Role = "admin"
	ac.SigningKeys.AddScopedSigner(scope)

	op, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	okp, err := ts.KeyStore.GetKeyPair(op.Subject)
	require.NoError(t, err)
	token, err := ac.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	_, err = ts.KeyStore.Store(skKP)
	require.NoError(t, err)

	ts.AddUserWithSigner(t, "A", "U", skKP)
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, skPub, uc.Issuer)

	_, err = ExecuteCmd(createReissueAccountCmd(), "--account", "A", "--force")
	require.NoError(t, err)

	ac2, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	// scoped signing key should still be present
	require.True(t, ac2.SigningKeys.Contains(skPub))

	// user should be re-signed with signing key and IssuerAccount set
	uc2, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, skPub, uc2.Issuer)
	require.Equal(t, ac2.Subject, uc2.IssuerAccount)
	require.True(t, ac2.DidSign(uc2))
}

func Test_ReissueAccountUserWithMissingScopedSigningKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, skPub, skKP := CreateAccountKey(t)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	scope := jwt.NewUserScope()
	scope.Key = skPub
	scope.Role = "admin"
	ac.SigningKeys.AddScopedSigner(scope)

	op, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	okp, err := ts.KeyStore.GetKeyPair(op.Subject)
	require.NoError(t, err)
	token, err := ac.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	_, err = ts.KeyStore.Store(skKP)
	require.NoError(t, err)

	ts.AddUserWithSigner(t, "A", "U", skKP)
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, skPub, uc.Issuer)

	// remove signing key
	ts.KeyStore.Remove(skPub)

	// preflight should warn about the missing key
	out, err := ExecuteCmd(createReissueAccountCmd(), "--account", "A")
	require.NoError(t, err)
	require.Contains(t, out.Out, "cannot be re-signed")
	require.Contains(t, out.Out, skPub)

	// force should succeed but warn
	out, err = ExecuteCmd(createReissueAccountCmd(), "--account", "A", "--force")
	require.NoError(t, err)
	require.Contains(t, out.Out, "cannot re-sign")
	require.Contains(t, out.Out, skPub)

	// account should have been reissued
	ac2, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotEqual(t, ac.Subject, ac2.Subject)
}

func Test_ReissueAllAccountsImportsUpdated(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "bar.>", 0, true)
	ts.AddAccount(t, "B")
	ts.AddImport(t, "A", jwt.Stream, "bar.>", "B")

	ac1, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	oldSubject := ac1.Subject

	_, err = ExecuteCmd(createReissueAccountCmd(), "--force")
	require.NoError(t, err)

	ac2, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotEqual(t, oldSubject, ac2.Subject)

	// B was also reissued, but its import should reference A's new subject
	bc2, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, bc2.Imports, 1)
	// when both are reissued, B's import.Account still references old A
	// because B was reissued with its imports as-is, and the cross-account
	// update skips reissued accounts. This is expected — both got new identities.
	// The import subject mapping should be updated.
	found := false
	for _, imp := range bc2.Imports {
		if strings.Contains(string(imp.Subject), "bar") {
			found = true
			// if A was reissued, B's import should reference A's new subject
			require.Equal(t, ac2.Subject, imp.Account,
				"import should reference A's new subject after all-account reissue")
		}
	}
	require.True(t, found, "expected to find bar import in B")
}

func Test_ReissueAccountPreflightPublicImport(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, true)
	ts.AddAccount(t, "B")
	ts.AddImport(t, "A", jwt.Stream, "foo.>", "B")

	out, err := ExecuteCmd(createReissueAccountCmd(), "--account", "A")
	require.NoError(t, err)
	require.Contains(t, out.Out, "public import will be updated")
	require.Contains(t, out.Out, "re-run with --force")
}

func Test_ReissueAccountPreflightPrivateImport(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, false)
	ts.AddAccount(t, "B")
	ts.AddImport(t, "A", jwt.Stream, "foo.>", "B")

	out, err := ExecuteCmd(createReissueAccountCmd(), "--account", "A")
	require.NoError(t, err)
	require.Contains(t, out.Out, "activation token can be re-signed")
	require.Contains(t, out.Out, "re-run with --force")
}
