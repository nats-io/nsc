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
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func Test_AddImport(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", false)

	ts.AddAccount(t, "B")

	token := ts.GenerateActivation(t, "A", "foobar.>", "B")
	fp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(fp, []byte(token)))

	tests := CmdTests{
		//{createAddImportCmd(), []string{"add", "import", "--account", "B"}, nil, []string{"token is required"}, true},
		{createAddImportCmd(), []string{"add", "import", "--account", "B", "--token", fp}, nil, []string{"added stream import"}, false},
	}

	tests.Run(t, "root", "add")
}

func Test_AddImportNoDefaultAccount(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

}

func Test_AddImportSelfImportsRejected(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", false)

	token := ts.GenerateActivation(t, "A", "foobar.>", "A")
	fp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(fp, []byte(token)))

	_, _, err := ExecuteCmd(createAddImportCmd(), "--token", fp)
	require.Error(t, err)
	require.Equal(t, "export issuer is this account", err.Error())
}

func Test_AddImportFromURL(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", false)

	ts.AddAccount(t, "B")

	token := ts.GenerateActivation(t, "A", "foobar.>", "B")

	ht := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, token)
	}))
	defer ht.Close()

	_, _, err := ExecuteCmd(createAddImportCmd(), "--account", "B", "--token", ht.URL)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, token, ac.Imports[0].Token)
}

func Test_AddImportInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", false)

	akp, err := ts.GetAccountKey(t, "A")
	require.NoError(t, err)
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()
	require.NoError(t, err)

	ts.AddAccount(t, "B")

	token := ts.GenerateActivation(t, "A", "foobar.>", "B")
	fp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(fp, []byte(token)))

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)
	input := []interface{}{1, false, false, fp, "my import", "barfoo.>", 0}
	_, _, err = ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, "my import", ac.Imports[0].Name)
	require.Equal(t, "barfoo.>", string(ac.Imports[0].To))
	require.Equal(t, "foobar.>", string(ac.Imports[0].Subject))
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddImportGeneratingTokenInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", false)

	akp, err := ts.GetAccountKey(t, "A")
	require.NoError(t, err)
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()
	require.NoError(t, err)

	ts.AddAccount(t, "B")

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)
	input := []interface{}{1, true, 1, "my import", "barfoo.>", 0}
	_, _, err = ExecuteInteractiveCmd(cmd, input)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, "my import", ac.Imports[0].Name)
	require.Equal(t, "barfoo.>", string(ac.Imports[0].To))
	require.Equal(t, "foobar.>", string(ac.Imports[0].Subject))
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddServiceImportGeneratingTokenInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foobar.>", false)

	akp, err := ts.GetAccountKey(t, "A")
	require.NoError(t, err)
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()
	require.NoError(t, err)

	ts.AddAccount(t, "B")

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)
	input := []interface{}{1, true, 1, "barfoo.xx", "my import", "foobar.yy"}
	_, _, err = ExecuteInteractiveCmd(cmd, input)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, "my import", ac.Imports[0].Name)
	require.Equal(t, "barfoo.xx", string(ac.Imports[0].To))
	require.Equal(t, "foobar.yy", string(ac.Imports[0].Subject))
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddPublicImport(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	pub := ts.GetAccountPublicKey(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", true)
	ts.AddAccount(t, "B")

	_, _, err := ExecuteCmd(createAddImportCmd(), "--account", "B", "--src-account", pub, "--remote-subject", "foobar.>")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Imports, 1)
}

func Test_AddImport_TokenAndPublic(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createAddImportCmd(), "--token", "/foo", "--remote-subject", "foobar.>")
	require.Error(t, err)
	require.Contains(t, err.Error(), "private imports require src-account")
}

func Test_AddImport_MoreForPublic(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createAddImportCmd(), "--remote-subject", "foobar.>")
	require.Error(t, err)
	require.Contains(t, err.Error(), "public imports require src-account, remote-subject")
}

func Test_AddImport_PublicInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foobar.>", true)

	akp, err := ts.GetAccountKey(t, "A")
	require.NoError(t, err)
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()
	require.NoError(t, err)

	ts.AddAccount(t, "B")

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)
	// B, public, A's pubkey, local sub, service, name test, remote subj "test.foobar.alberto, key
	input := []interface{}{1, false, true, apub, "foobar.x", true, "test", "test.foobar.alberto", 0}
	_, _, err = ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, "test", ac.Imports[0].Name)
	// for services remote local is subject, remote is to
	require.Equal(t, "test.foobar.alberto", string(ac.Imports[0].Subject))
	require.Equal(t, "foobar.x", string(ac.Imports[0].To))
	require.Equal(t, jwt.Service, ac.Imports[0].Type)
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddImport_PublicStreamInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foobar.>", true)

	akp, err := ts.GetAccountKey(t, "A")
	require.NoError(t, err)
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()
	require.NoError(t, err)

	ts.AddAccount(t, "B")

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)
	// B, don't pick, public, A's pubkey, remote sub, stream, name test, local subj "test.foobar.>, key
	input := []interface{}{1, false, true, apub, "foobar.>", false, "test", "test.foobar.>", 0}
	_, _, err = ExecuteInteractiveCmd(cmd, input)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, "test", ac.Imports[0].Name)
	require.Equal(t, "test.foobar.>", string(ac.Imports[0].To))
	require.Equal(t, "foobar.>", string(ac.Imports[0].Subject))
	require.Equal(t, jwt.Stream, ac.Imports[0].Type)
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddImportWithSigningKeyToken(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, pk, sk := CreateAccountKey(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", false)

	ts.AddAccount(t, "B")
	token := ts.GenerateActivationWithSigner(t, "A", "foobar.>", "B", sk)
	tp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(tp, []byte(token)))
	bc, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)

	// decode the activation
	acc, err := jwt.DecodeActivationClaims(token)
	require.NoError(t, err)
	// issuer is the signing key
	require.Equal(t, acc.Issuer, pk)
	// issuer account is account A
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, acc.IssuerAccount, ac.Subject)
	// account to import is B
	require.Equal(t, acc.Subject, bc.Subject)

	_, _, err = ExecuteCmd(createAddImportCmd(), "--account", "B", "--token", tp)
	require.NoError(t, err)
	acb, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, acb.Imports, 1)
	require.Equal(t, acb.Imports[0].Account, ac.Subject)
}
