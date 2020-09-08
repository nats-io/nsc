/*
 * Copyright 2018-2019 The NATS Authors
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
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_GenerateActivation(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", false)

	_, pub, _ := CreateAccountKey(t)

	tests := CmdTests{
		{createGenerateActivationCmd(), []string{"generate", "activation"}, nil, []string{"target-account cannot be empty"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--target-account", pub}, []string{"-----BEGIN NATS ACTIVATION JWT-----"}, nil, false},
	}

	tests.Run(t, "root", "generate")
}

func Test_GenerateActivationMultiple(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", false)
	ts.AddExport(t, "A", jwt.Stream, "bar.>", false)
	ts.AddAccount(t, "B")

	_, pub, _ := CreateAccountKey(t)

	tests := CmdTests{
		{createGenerateActivationCmd(), []string{"generate", "activation", "--account", "A"}, nil, []string{"a subject is required"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--account", "A", "--subject", "bar.>"}, nil, []string{"target-account cannot be empty"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--account", "A", "--subject", "bar.>", "--target-account", pub}, []string{"-----BEGIN NATS ACTIVATION JWT-----"}, nil, false},
	}

	tests.Run(t, "root", "generate")
}

func Test_GenerateActivationMultipleAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", false)
	ts.AddExport(t, "A", jwt.Stream, "bar.>", false)
	ts.AddAccount(t, "B")
	GetConfig().SetAccount("")
	_, _, err := ExecuteCmd(createGenerateActivationCmd())
	require.Error(t, err)
	require.Contains(t, err.Error(), "account is required")
}

func Test_GenerateActivationEmptyExports(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createGenerateActivationCmd())
	require.Error(t, err)
	require.Equal(t, "account \"A\" doesn't have exports", err.Error())
}

func Test_GenerateActivationNoPrivateExports(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foo", true)

	_, _, err := ExecuteCmd(createGenerateActivationCmd())
	require.Error(t, err)
	require.Equal(t, "account \"A\" doesn't have exports that require an activation token", err.Error())
}

func Test_GenerateActivationOutputsFile(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foo", false)

	_, pub, _ := CreateAccountKey(t)

	outpath := filepath.Join(ts.Dir, "token.jwt")
	_, _, err := ExecuteCmd(createGenerateActivationCmd(), "--target-account", pub, "--output-file", outpath)
	require.NoError(t, err)
	testExternalToken(t, outpath)
}

func testExternalToken(t *testing.T, tokenpath string) {
	_, err := os.Stat(tokenpath)
	require.NoError(t, err)

	d, err := ioutil.ReadFile(tokenpath)
	require.NoError(t, err)

	s, err := jwt.ParseDecoratedJWT(d)
	require.NoError(t, err)

	ac, err := jwt.DecodeActivationClaims(s)
	if err != nil && strings.Contains(err.Error(), "illegal base64") {
		t.Log("failed decoding a claim")
		t.Log("Extracted token\n", s)
		t.Log("Token file", tokenpath)
	}
	require.NoError(t, err)
	require.Equal(t, "foo", string(ac.ImportSubject))
}

func Test_InteractiveGenerate(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foo", false)

	cmd := createGenerateActivationCmd()
	HoistRootFlags(cmd)

	_, pub, _ := CreateAccountKey(t)

	outpath := filepath.Join(ts.Dir, "token.jwt")
	inputs := []interface{}{0, "foo", pub, "0", "0"}
	_, _, err := ExecuteInteractiveCmd(cmd, inputs, "-i", "--output-file", outpath)
	require.NoError(t, err)

	testExternalToken(t, outpath)
}

func Test_InteractiveExternalKeyGenerate(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foo", false)

	cmd := createGenerateActivationCmd()
	HoistRootFlags(cmd)

	outpath := filepath.Join(ts.Dir, "token.jwt")

	_, pub, _ := CreateAccountKey(t)

	inputs := []interface{}{0, "foo", pub, "0", "0"}
	_, _, err := ExecuteInteractiveCmd(cmd, inputs, "-i", "--output-file", outpath)
	require.NoError(t, err)

	testExternalToken(t, outpath)
}

func Test_InteractiveMultipleAccountsGenerate(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "foo", false)
	ts.AddAccount(t, "B")

	cmd := createGenerateActivationCmd()
	HoistRootFlags(cmd)

	outpath := filepath.Join(ts.Dir, "token.jwt")

	_, pub, _ := CreateAccountKey(t)
	inputs := []interface{}{0, 0, "foo", pub, "0", "0"}
	_, _, err := ExecuteInteractiveCmd(cmd, inputs, "-i", "--output-file", outpath)
	require.NoError(t, err)

	testExternalToken(t, outpath)
}

func Test_GenerateActivationUsingSigningKey(t *testing.T) {
	ts := NewTestStore(t, "gen activation")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	sk, pk, _ := CreateAccountKey(t)
	ts.AddExport(t, "A", jwt.Stream, "foo", false)
	_, _, err := ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)

	_, tpk, _ := CreateAccountKey(t)

	outpath := filepath.Join(ts.Dir, "token.jwt")
	_, _, err = ExecuteCmd(HoistRootFlags(createGenerateActivationCmd()), "-t", tpk, "-s", "foo", "-o", outpath, "-K", string(sk))
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	d, err := ioutil.ReadFile(outpath)
	require.NoError(t, err)

	token, err := jwt.ParseDecoratedJWT(d)
	require.NoError(t, err)
	actc, err := jwt.DecodeActivationClaims(token)
	require.NoError(t, err)
	require.Equal(t, actc.Issuer, pk)
	require.True(t, ac.DidSign(actc))
	require.Equal(t, actc.IssuerAccount, ac.Subject)
}

func Test_InteractiveGenerateActivationPush(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp)
	defer as.Close()

	ts := NewTestStoreWithOperator(t, "T", okp)
	defer ts.Done(t)
	err := ts.Store.StoreRaw(m["operator"])
	require.NoError(t, err)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", false)

	_, apk, _ := CreateAccountKey(t)

	tf := filepath.Join(ts.Dir, "token.jwt")
	inputs := []interface{}{0, "q", apk, "0", "0", true}
	_, _, err = ExecuteInteractiveCmd(createGenerateActivationCmd(), inputs, "--output-file", tf)
	require.NoError(t, err)

	d, err := Read(tf)
	require.NoError(t, err)
	tok, err := jwt.ParseDecoratedJWT(d)
	require.NoError(t, err)

	ac, err := jwt.DecodeActivationClaims(tok)
	require.NoError(t, err)
	id, err := ac.HashID()
	require.NoError(t, err)
	require.Contains(t, m, id)
	require.Equal(t, []byte(tok), m[id])
}
