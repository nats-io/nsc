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
	jwt "github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
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
