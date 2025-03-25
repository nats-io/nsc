// Copyright 2025 The NATS Authors
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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_ExportEnvOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, err := ExecuteCmd(createEditOperatorCmd(), "--sk", "generate")
	require.NoError(t, err)

	_, sk2, _ := CreateOperatorKey(t)

	_, err = ExecuteCmd(createEditOperatorCmd(), "--sk", sk2)
	require.NoError(t, err)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Len(t, oc.SigningKeys, 2)
	require.Equal(t, oc.SigningKeys[1], sk2)
	kp, err := ts.KeyStore.GetKeyPair(oc.SigningKeys[0])
	require.NoError(t, err)
	sk1, err := kp.PublicKey()
	require.NoError(t, err)
	require.NotNil(t, kp)

	_, err = ExecuteCmd(CreateAddAccountCmd(), "A")
	require.NoError(t, err)
	_, err = ExecuteCmd(createEditAccount(), "--sk", "generate")
	require.NoError(t, err)
	_, err = ExecuteCmd(createAddExportCmd(), "--subject", "q.*", "--service", "--private")
	require.NoError(t, err)
	_, err = ExecuteCmd(CreateAddUserCmd(), "a")
	require.NoError(t, err)

	_, err = ExecuteCmd(CreateAddAccountCmd(), "B")
	require.NoError(t, err)
	token := filepath.Join(ts.Dir, "/activation.jwt")
	_, err = ExecuteCmd(createGenerateActivationCmd(), "--account", "A", "--target-account", "B", "--subject", "q.B", "--output-file", token)
	require.NoError(t, err)
	_, err = ExecuteCmd(createAddImportCmd(), "--account", "B", "--token", token)
	require.NoError(t, err)

	exportFile := filepath.Join(ts.Dir, "o.json")
	_, err = ExecuteCmd(createExportEnvironmentCmd(), "--name", "O", "--out", exportFile)
	require.NoError(t, err)

	d, err := os.ReadFile(exportFile)
	require.NoError(t, err)

	var env Environment
	require.NoError(t, json.Unmarshal(d, &env))

	require.Len(t, env.Operators, 1)
	O := env.Operators[0]
	require.Equal(t, O.Name, "O")
	require.Equal(t, O.Key.Key, oc.Subject)
	// the exported operator will only list one of the signing keys since it only has one
	// of the signing key seeds
	require.Len(t, O.SigningKeys, 1)
	require.Equal(t, O.SigningKeys[0].Key, sk1)
	d, err = ts.Store.ReadRawOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, O.Jwt, string(d))
	o2, err := jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)
	require.Len(t, o2.SigningKeys, 2)
	require.Equal(t, o2.SigningKeys[0], sk1)
	require.Equal(t, o2.SigningKeys[1], sk2)

	require.Len(t, O.Accounts, 2)
	A := O.Accounts[0]
	require.Equal(t, A.Name, "A")
	require.Len(t, A.SigningKeys, 1)
	require.Len(t, A.Users, 1)

	B := O.Accounts[1]
	require.Equal(t, B.Name, "B")
	require.Len(t, B.SigningKeys, 0)
	require.Len(t, B.Users, 0)

	ResetForTests()

	ts2 := NewEmptyStore(t)
	defer ts2.Done(t)

	_, err = ExecuteCmd(createImportEnvironment(), "--in", exportFile)
	require.NoError(t, err)
	// the store dir for the operator is there, but the store was loaded empty
	ts2.SwitchOperator(t, "O")

	require.NotEqual(t, ts2.Store.Dir, ts.Store.Dir)

	oc2, err := ts2.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotNil(t, oc2)
	require.Equal(t, oc2.Name, "O")

	kp, err = ts2.KeyStore.GetKeyPair(oc.Subject)
	require.NoError(t, err)
	require.NotNil(t, kp)

	kp, err = ts2.KeyStore.GetKeyPair(oc.SigningKeys[0])
	require.NoError(t, err)
	require.NotNil(t, kp)
	require.Equal(t, oc.SigningKeys[0], sk1)

	// we don't have one of the keys
	require.Equal(t, oc.SigningKeys[1], sk2)
	kp, err = ts2.KeyStore.GetKeyPair(oc.SigningKeys[1])
	require.NoError(t, err)
	require.Nil(t, kp)

	ac, err := ts2.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Exports, 1)
	require.Len(t, ac.SigningKeys, 1)

	u, err := ts2.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, u)

	bc, err := ts2.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, bc.Imports, 1)
}

func Test_ExportEnvNoOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	require.NoError(t, os.Remove(filepath.Join(ts.Dir, "stores", "O", "O.jwt")))

	exportFile := filepath.Join(ts.Dir, "o.json")
	_, err := ExecuteCmd(createExportEnvironmentCmd(), "--name", "O", "--out", exportFile)
	require.Error(t, err)
	require.Contains(t, err.Error(), "operator O does not exist")
}

func Test_ImportEnvNoOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	var env Environment
	d, err := json.MarshalIndent(env, "", " ")
	require.NoError(t, err)
	out := filepath.Join(ts.Dir, "o.json")
	require.NoError(t, os.WriteFile(out, d, 0644))

	_, err = ExecuteCmd(createImportEnvironment(), "--in", out)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no operators in the input file")
}

func Test_ExportEnvNoOperatorNoKeys(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, err := ExecuteCmd(createEditOperatorCmd(), "--sk", "generate")
	require.NoError(t, err)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "u")

	require.NoError(t, os.RemoveAll(ts.KeysDir))

	exportFile := filepath.Join(ts.Dir, "o.json")
	_, err = ExecuteCmd(createExportEnvironmentCmd(), "--name", "O", "--out", exportFile)
	require.NoError(t, err)

	d, _ := os.ReadFile(exportFile)
	t.Log(string(d))

	ts2 := NewEmptyStore(t)
	defer ts2.Done(t)

	_, err = ExecuteCmd(createImportEnvironment(), "--in", exportFile)
	require.NoError(t, err)
	// the store dir for the operator is there, but the store was loaded empty
	ts2.SwitchOperator(t, "O")
	oc, err := ts2.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)
	require.Equal(t, oc.Name, "O")
	require.Nil(t, ts2.OperatorKey)
	require.Len(t, oc.SigningKeys, 1)
	kp, err := ts.KeyStore.GetKeyPair(oc.SigningKeys[0])
	require.NoError(t, err)
	require.Nil(t, kp)

	ac, err := ts2.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	kp, err = ts2.KeyStore.GetKeyPair(ac.Subject)
	require.NoError(t, err)
	require.Nil(t, kp)

	uc, err := ts2.Store.ReadUserClaim("A", "u")
	require.NoError(t, err)
	require.NotNil(t, uc)
	kp, err = ts2.KeyStore.GetKeyPair(uc.Subject)
	require.NoError(t, err)
	require.Nil(t, kp)
}

func Test_ImportOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, err := ExecuteCmd(createEditOperatorCmd(), "--sk", "generate")
	require.NoError(t, err)

	// edit the operator to have a signing key
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	oid := oc.Subject
	osk := oc.SigningKeys[0]

	oskp, err := ts.KeyStore.GetKeyPair(osk)
	require.NoError(t, err)
	require.NotNil(t, oskp)
	ts.AddAccountWithSigner(t, "A", oskp)

	_, err = ExecuteCmd(createEditAccount(), "--sk", "generate")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	aid := ac.Subject
	ask := ac.SigningKeys.Keys()[0]
	askp, err := ts.KeyStore.GetKeyPair(ask)
	require.NoError(t, err)

	// add user with signing key
	ts.AddUserWithSigner(t, "A", "u", askp)
	upk := ts.GetUserPublicKey(t, "A", "u")

	// export the env
	exportFile := filepath.Join(ts.Dir, "o.json")
	_, err = ExecuteCmd(createExportEnvironmentCmd(), "--name", "O", "--out", exportFile)
	require.NoError(t, err)

	//var environment Environment
	//d, err := os.ReadFile(exportFile)
	//require.NoError(t, json.Unmarshal(d, &environment))
	//d, err = json.MarshalIndent(environment, "", " ")
	//t.Logf("%v", string(d))
	//require.NoError(t, environment.Reissue())
	//
	//d, err = json.MarshalIndent(environment, "", " ")
	//t.Logf("%v", string(d))

	// try to import should fail, as we have the operator
	_, err = ExecuteCmd(createImportEnvironment(), "--in", exportFile)
	require.Error(t, err)
	require.Contains(t, err.Error(), "operator O already exists")

	// force allows it to succeed
	_, err = ExecuteCmd(createImportEnvironment(), "--force", "--in", exportFile)
	require.NoError(t, err)

	// check the keys match
	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, oid, oc.Subject)
	require.Equal(t, osk, oc.SigningKeys[0])

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, aid, ac.Subject)
	require.Equal(t, ask, ac.SigningKeys.Keys()[0])

	uc, err := ts.Store.ReadUserClaim("A", "u")
	require.NoError(t, err)
	require.Equal(t, upk, uc.Subject)
	require.Equal(t, ask, uc.Issuer)
	require.Equal(t, aid, uc.IssuerAccount)

	// re-import again, but this time use a different operator name
	_, err = ExecuteCmd(createImportEnvironment(), "--rename", "OO", "--in", exportFile)
	require.NoError(t, err)
	ts.SwitchOperator(t, "OO")

	// check the keys match
	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, oid, oc.Subject)
	require.Equal(t, osk, oc.SigningKeys[0])

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, aid, ac.Subject)
	require.Equal(t, ask, ac.SigningKeys.Keys()[0])

	uc, err = ts.Store.ReadUserClaim("A", "u")
	require.NoError(t, err)
	require.Equal(t, upk, uc.Subject)
	require.Equal(t, ask, uc.Issuer)
	require.Equal(t, aid, uc.IssuerAccount)

	// re-import again, but this time, use overwrite and reissue the secrets
	_, err = ExecuteCmd(createImportEnvironment(), "--reissue", "--force", "--in", exportFile)
	require.NoError(t, err)
	ts.SwitchOperator(t, "O")

	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotEqual(t, oid, oc.Subject)
	require.NotEqual(t, osk, oc.SigningKeys[0])

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotEqual(t, aid, ac.Subject)
	require.NotEqual(t, ask, ac.SigningKeys.Keys()[0])

	uc, err = ts.Store.ReadUserClaim("A", "u")
	require.NoError(t, err)
	require.NotEqual(t, upk, uc.Subject)
	require.NotEqual(t, ask, uc.Issuer)
	require.NotEqual(t, aid, uc.IssuerAccount)
}

func Test_ImportOperatorTransformation(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "u")

	// export the env
	exportFile := filepath.Join(ts.Dir, "o.json")
	_, err := ExecuteCmd(createExportEnvironmentCmd(), "--name", "O", "--out", exportFile)
	require.NoError(t, err)

	var a Environment
	d, err := os.ReadFile(exportFile)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(d, &a))

	var b Environment
	require.NoError(t, json.Unmarshal(d, &b))
	require.NoError(t, b.Reissue())

	require.NotEqual(t, a.Operators[0].Key.Key, b.Operators[0].Key.Key)
	oc, err := jwt.DecodeOperatorClaims(b.Operators[0].Jwt)
	require.NoError(t, err)
	require.Equal(t, b.Operators[0].Key.Key, oc.Subject)

	ac, err := jwt.DecodeAccountClaims(b.Operators[0].Accounts[0].Jwt)
	require.NoError(t, err)
	require.NotEqual(t, a.Operators[0].Accounts[0].Key.Key, ac.Subject)
	require.Equal(t, b.Operators[0].Accounts[0].Key.Key, ac.Subject)
	require.Equal(t, b.Operators[0].Key.Key, ac.Issuer)

	uc, err := jwt.DecodeUserClaims(b.Operators[0].Accounts[0].Users[0].Jwt)
	require.NoError(t, err)
	require.NotEqual(t, a.Operators[0].Accounts[0].Users[0].Key.Key, uc.Subject)
	require.Equal(t, b.Operators[0].Accounts[0].Users[0].Key.Key, uc.Subject)
	require.Equal(t, b.Operators[0].Accounts[0].Key.Key, uc.Issuer)
}

func Test_ImportOperatorSigningKeyTransformation(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, err := ExecuteCmd(createEditOperatorCmd(), "--sk", "generate")
	require.NoError(t, err)
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	ts.AddAccount(t, "A")

	_, err = ExecuteCmd(HoistRootFlags(createEditAccount()), "--sk", "generate", "-K", oc.SigningKeys[0])
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "u", "-K", ac.SigningKeys.Keys()[0])
	require.NoError(t, err)

	// export the env
	exportFile := filepath.Join(ts.Dir, "o.json")
	_, err = ExecuteCmd(createExportEnvironmentCmd(), "--name", "O", "--out", exportFile)
	require.NoError(t, err)

	var a Environment
	d, err := os.ReadFile(exportFile)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(d, &a))

	var b Environment
	require.NoError(t, json.Unmarshal(d, &b))
	require.NoError(t, b.Reissue())

	ac, err = jwt.DecodeAccountClaims(b.Operators[0].Accounts[0].Jwt)
	require.NoError(t, err)
	require.NotEqual(t, a.Operators[0].Accounts[0].Key.Key, ac.Subject)
	require.Equal(t, b.Operators[0].Accounts[0].Key.Key, ac.Subject)
	require.NotEqual(t, a.Operators[0].SigningKeys[0].Key, ac.Issuer)
	require.Equal(t, b.Operators[0].SigningKeys[0].Key, ac.Issuer)

	uc, err := jwt.DecodeUserClaims(b.Operators[0].Accounts[0].Users[0].Jwt)
	require.NoError(t, err)
	require.NotEqual(t, a.Operators[0].Accounts[0].Users[0].Key.Key, uc.Subject)
	require.Equal(t, b.Operators[0].Accounts[0].Users[0].Key.Key, uc.Subject)
	require.NotEqual(t, b.Operators[0].Accounts[0].Key.Key, uc.Issuer)
	require.NotEqual(t, a.Operators[0].Accounts[0].Key.Key, b.Operators[0].Accounts[0].Key.Key)
	require.NotEqual(t, a.Operators[0].Accounts[0].SigningKeys[0].Key, b.Operators[0].Accounts[0].SigningKeys[0].Key)
	require.Equal(t, b.Operators[0].Accounts[0].Key.Key, uc.IssuerAccount)
	require.Equal(t, b.Operators[0].Accounts[0].SigningKeys[0].Key, uc.Issuer)
}
