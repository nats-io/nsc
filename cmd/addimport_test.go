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
	ts.AddAccount(t, "B")

	kp, err := ts.KeyStore.GetAccountKey("B")
	require.NoError(t, err)
	require.NotNil(t, kp)
	d, err := kp.PublicKey()

	token := ts.GenerateActivation(t, string(d), "A", jwt.Stream, "foobar.>")
	fp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(fp, []byte(token)))

	tests := CmdTests{
		{createAddImportCmd(), []string{"add", "import"}, nil, []string{"an account is required"}, true},
		{createAddImportCmd(), []string{"add", "import", "--account", "B"}, nil, []string{"token is required"}, true},
		{createAddImportCmd(), []string{"add", "import", "--account", "B", "--token", fp}, nil, []string{"added stream import"}, false},
	}

	tests.Run(t, "root", "add")
}

func Test_AddImportSelfImportsRejected(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	kp, err := ts.KeyStore.GetAccountKey("A")
	require.NoError(t, err)
	require.NotNil(t, kp)
	d, err := kp.PublicKey()

	token := ts.GenerateActivation(t, d, "A", jwt.Stream, "foobar.>")
	fp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(fp, []byte(token)))

	_, _, err = ExecuteCmd(createAddImportCmd(), "--token", fp)
	require.Error(t, err)
	require.Equal(t, "activation issuer is this account", err.Error())
}

func Test_AddImportFromURL(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	ts.AddAccount(t, "B")
	kp, err := ts.KeyStore.GetAccountKey("B")
	require.NoError(t, err)
	require.NotNil(t, kp)
	d, err := kp.PublicKey()

	token := ts.GenerateActivation(t, d, "A", jwt.Stream, "foobar.>")

	ht := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, token)
	}))
	defer ht.Close()

	_, _, err = ExecuteCmd(createAddImportCmd(), "--account", "B", "--token", ht.URL)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.Len(t, ac.Imports, 1)
	require.Equal(t, ac.Imports[0].Token, ht.URL)
}

func Test_AddImportInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	akp, err := ts.KeyStore.GetAccountKey("A")
	require.NoError(t, err)
	require.NotNil(t, akp)
	apub, err := akp.PublicKey()

	ts.AddAccount(t, "B")
	bkp, err := ts.KeyStore.GetAccountKey("B")
	require.NoError(t, err)
	require.NotNil(t, bkp)
	bpub, err := bkp.PublicKey()

	token := ts.GenerateActivation(t, bpub, "A", jwt.Stream, "foobar.>")
	fp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(fp, []byte(token)))

	cmd := createAddImportCmd()
	HoistRootFlags(cmd)
	input := []interface{}{1, fp, "my import", "barfoo.>"}
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
