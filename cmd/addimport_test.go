/*
 * Copyright 2018-2023 The NATS Authors
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
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_AddImport(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, false)

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
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, false)

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
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, false)

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
	require.Len(t, ac.Imports, 1)
	require.Equal(t, token, ac.Imports[0].Token)
}

func Test_AddImportInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, false)

	akp := ts.GetAccountKey(t, "A")
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
	require.Equal(t, "barfoo.>", string(ac.Imports[0].LocalSubject))
	require.Equal(t, "foobar.>", string(ac.Imports[0].Subject))
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddImportGeneratingTokenInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, false)

	akp := ts.GetAccountKey(t, "A")
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
	require.Equal(t, "barfoo.>", string(ac.Imports[0].LocalSubject))
	require.Equal(t, "foobar.>", string(ac.Imports[0].Subject))
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddServiceImportGeneratingTokenInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foobar.>", 0, false)

	akp := ts.GetAccountKey(t, "A")
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()
	require.NoError(t, err)

	ts.AddAccount(t, "B")

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)
	input := []interface{}{1, true, 1, "barfoo.>", true, "my import", "foobar.>"}
	_, _, err = ExecuteInteractiveCmd(cmd, input)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, true, ac.Imports[0].Share)
	require.Equal(t, "my import", ac.Imports[0].Name)
	require.Equal(t, "foobar.>", string(ac.Imports[0].LocalSubject))
	require.Equal(t, "barfoo.>", string(ac.Imports[0].Subject))
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddPublicImport(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, true)
	ts.AddAccount(t, "B")

	_, _, err := ExecuteCmd(createAddImportCmd(), "--account", "B", "--src-account", "A", "--remote-subject", "foobar.>")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
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
	ts.AddExport(t, "A", jwt.Service, "foobar.>", 0, true)

	akp := ts.GetAccountKey(t, "A")
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()
	require.NoError(t, err)

	ts.AddAccount(t, "B")

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)
	// B, public, A's pubkey, local sub, service, name test, remote subj "test.foobar.alberto, key
	input := []interface{}{1, false, true, apub, "foobar.x.*", true, "test", "test.foobar.alberto.*", 0}
	_, _, err = ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, "test", ac.Imports[0].Name)
	// for services remote local is subject, remote is to
	require.Equal(t, "foobar.x.*", string(ac.Imports[0].Subject))
	require.Equal(t, "test.foobar.alberto.*", string(ac.Imports[0].LocalSubject))
	require.Equal(t, jwt.Service, ac.Imports[0].Type)
	require.Equal(t, apub, ac.Imports[0].Account)
}

func Test_AddImport_PublicImportsInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, true)
	ts.AddExport(t, "A", jwt.Service, "q.*", 0, true)

	akp := ts.GetAccountKey(t, "A")
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
	require.Equal(t, "test.foobar.>", string(ac.Imports[0].LocalSubject))
	require.Equal(t, "foobar.>", string(ac.Imports[0].Subject))
	require.True(t, ac.Imports[0].IsStream())
	require.Equal(t, apub, ac.Imports[0].Account)

	// B, don't pick, public, A's pubkey, remote sub, service, name test, local subj "test.foobar.>, key
	input = []interface{}{1, false, true, apub, "q.*", true, "q", "qq.*", 0}
	_, _, err = ExecuteInteractiveCmd(cmd, input)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 2)
	require.Equal(t, "q", ac.Imports[1].Name)
	require.Equal(t, "qq.*", string(ac.Imports[1].LocalSubject))
	require.Equal(t, "q.*", string(ac.Imports[1].Subject))
	require.True(t, ac.Imports[1].IsService())
	require.Equal(t, apub, ac.Imports[1].Account)
}

func Test_AddImportWithSigningKeyToken(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, pk, sk := CreateAccountKey(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, false)

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

func Test_AddDecoratedToken(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, pk, sk := CreateAccountKey(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, false)

	ts.AddAccount(t, "B")
	token := ts.GenerateActivationWithSigner(t, "A", "foobar.>", "B", sk)
	d, err := jwt.DecorateJWT(token)
	require.NoError(t, err)
	token = string(d)
	tp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(tp, []byte(token)))

	_, _, err = ExecuteCmd(createAddImportCmd(), "--account", "B", "--token", tp)
	require.NoError(t, err)
	acb, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, acb.Imports, 1)
	require.Equal(t, string(acb.Imports[0].Subject), "foobar.>")
}

func Test_AddImport_LocalImportsInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, true)
	ts.AddExport(t, "A", jwt.Service, "q", 0, true)

	akp := ts.GetAccountKey(t, "A")
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()
	require.NoError(t, err)

	ts.AddAccount(t, "B")

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)

	// B, pick, stream foobar, name test, local subj "test.foobar.>, key
	input := []interface{}{1, true, 1, "test", "test.foobar.>"}
	_, _, err = ExecuteInteractiveCmd(cmd, input)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, false, ac.Imports[0].Share)
	require.Equal(t, "test", ac.Imports[0].Name)
	require.Equal(t, "test.foobar.>", string(ac.Imports[0].LocalSubject))
	require.Equal(t, "foobar.>", string(ac.Imports[0].Subject))
	require.True(t, ac.Imports[0].IsStream())
	require.Equal(t, apub, ac.Imports[0].Account)

	// B, pick, service q, name q service, local subj qq
	input = []interface{}{1, true, 2, true, "q service", "qq", 0}
	_, _, err = ExecuteInteractiveCmd(cmd, input)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 2)
	require.Equal(t, true, ac.Imports[1].Share)
	require.Equal(t, "q service", ac.Imports[1].Name)
	require.Equal(t, "qq", string(ac.Imports[1].LocalSubject))
	require.Equal(t, "q", string(ac.Imports[1].Subject))
	require.True(t, ac.Imports[1].IsService())
	require.Equal(t, apub, ac.Imports[1].Account)
}

func Test_ImportStreamHandlesDecorations(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foobar.>", 0, false)

	ts.AddAccount(t, "B")
	ac := ts.GenerateActivation(t, "A", "foobar.>", "B")
	// test util removed the decoration
	d, err := jwt.DecorateJWT(ac)
	require.NoError(t, err)

	ap := filepath.Join(ts.Dir, "activation.jwt")
	Write(ap, d)
	_, _, err = ExecuteCmd(createAddImportCmd(), "--account", "B", "--token", ap)
	require.NoError(t, err)

	bc, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, bc.Imports, 1)
	require.Empty(t, bc.Imports[0].LocalSubject)
}

func Test_ImportServiceHandlesDecorations(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", 0, false)

	ts.AddAccount(t, "B")
	ac := ts.GenerateActivation(t, "A", "q", "B")
	// test util removed the decoration
	d, err := jwt.DecorateJWT(ac)
	require.NoError(t, err)

	ap := filepath.Join(ts.Dir, "activation.jwt")
	Write(ap, d)
	_, _, err = ExecuteCmd(createAddImportCmd(), "--account", "B", "--token", ap)
	require.NoError(t, err)

	bc, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, bc.Imports, 1)
	require.Equal(t, jwt.Subject(bc.Imports[0].LocalSubject), bc.Imports[0].Subject)
}

func Test_AddImportToAccount(t *testing.T) {
	ts := NewTestStore(t, t.Name())
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	bpk := ts.GetAccountPublicKey(t, "B")

	_, _, err := ExecuteCmd(createAddImportCmd(), "--account", "A", "--src-account", bpk, "--remote-subject", "s.>")
	require.NoError(t, err)

	bc, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, bc.Imports, 1)
}

func Test_AddWilcdardImport(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "B")
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "priv-srvc.>", 0, false)
	ts.AddExport(t, "A", jwt.Stream, "priv-strm.>", 0, false)
	ts.AddExport(t, "A", jwt.Service, "pub-srvc.>", 0, true)
	ts.AddExport(t, "A", jwt.Stream, "pub-strm.>", 0, true)

	aPub := ts.GetAccountPublicKey(t, "A")

	srvcToken := ts.GenerateActivation(t, "A", "priv-srvc.>", "B")
	srvcFp := filepath.Join(ts.Dir, "srvc-token.jwt")
	require.NoError(t, Write(srvcFp, []byte(srvcToken)))
	defer os.Remove(srvcFp)

	strmToken := ts.GenerateActivation(t, "A", "priv-strm.>", "B")
	strmFp := filepath.Join(ts.Dir, "strm-token.jwt")
	require.NoError(t, Write(strmFp, []byte(strmToken)))
	defer os.Remove(strmFp)

	tests := CmdTests{
		{createAddImportCmd(), []string{"add", "import", "--account", "B", "--token", srvcFp}, nil,
			[]string{"added service import"}, false},
		{createAddImportCmd(), []string{"add", "import", "--account", "B", "--token", strmFp}, nil,
			[]string{"added stream import"}, false},
		{createAddImportCmd(), []string{"add", "import", "--account", "B", "--src-account", aPub, "--service",
			"--remote-subject", "pub-srvc.>"}, nil, []string{"added service import"}, false},
		{createAddImportCmd(), []string{"add", "import", "--account", "B", "--src-account", aPub,
			"--remote-subject", "pub-strm.>"}, nil, []string{"added stream import"}, false},
	}

	tests.Run(t, "root", "add")
}

func TestAddImport_SameName(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "database")
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "stream.database", 0, false)
	ts.AddAccount(t, "B")
	ts.AddExport(t, "B", jwt.Stream, "stream.database", 0, false)

	// account, locally available, name, local subj,
	// database, true, A: -> stream.database, "stream.database", "ingest
	input := []interface{}{2, true, 1, "ingest.a", "ingest.a"}
	_, _, err := ExecuteInteractiveCmd(createAddImportCmd(), input)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("database")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, "ingest.a", ac.Imports[0].Name)
	require.Equal(t, "ingest.a", string(ac.Imports[0].LocalSubject))
	require.Equal(t, "stream.database", string(ac.Imports[0].Subject))
	require.True(t, ac.Imports[0].IsStream())
	require.Equal(t, ts.GetAccountPublicKey(t, "A"), ac.Imports[0].Account)

	input = []interface{}{2, true, 3, "ingest.b", "ingest.b"}
	_, _, err = ExecuteInteractiveCmd(createAddImportCmd(), input)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("database")
	require.NoError(t, err)
	require.Len(t, ac.Imports, 2)
	require.Equal(t, "ingest.b", ac.Imports[1].Name)
	require.Equal(t, "ingest.b", string(ac.Imports[1].LocalSubject))
	require.Equal(t, "stream.database", string(ac.Imports[1].Subject))
	require.True(t, ac.Imports[1].IsStream())
	require.Equal(t, ts.GetAccountPublicKey(t, "B"), ac.Imports[1].Account)
}
