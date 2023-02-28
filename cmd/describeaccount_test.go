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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func TestDescribeAccount_Single(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	opub := ts.GetOperatorPublicKey(t)

	ts.AddAccount(t, "A")
	pub := ts.GetAccountPublicKey(t, "A")

	stdout, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	// account A public key
	require.Contains(t, stdout, pub)
	// operator public key
	require.Contains(t, stdout, opub)
	// name for the account
	require.Contains(t, stdout, " A ")
}

func TestDescribeAccountRaw(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	Raw = true
	stdout, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)

	ac, err := jwt.DecodeAccountClaims(stdout)
	require.NoError(t, err)

	require.NotNil(t, ac)
	require.Equal(t, "A", ac.Name)
}

func TestDescribeAccount_Multiple(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	out, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	out = StripTableDecorations(out)
	require.Contains(t, out, "Name B")
}

func TestDescribeAccount_MultipleAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	require.NoError(t, GetConfig().SetAccount(""))

	_, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.Error(t, err)
	require.Contains(t, err.Error(), "account is required")
}

func TestDescribeAccount_MultipleWithContext(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	err := GetConfig().SetAccount("B")
	require.NoError(t, err)

	opub := ts.GetOperatorPublicKey(t)
	require.NoError(t, err)

	pub := ts.GetAccountPublicKey(t, "B")

	stdout, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, opub)
	require.Contains(t, stdout, " B ")
}

func TestDescribeAccount_MultipleWithFlag(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	pub := ts.GetAccountPublicKey(t, "B")

	stdout, _, err := ExecuteCmd(createDescribeAccountCmd(), "--name", "B")
	require.NoError(t, err)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, " B ")
}

func TestDescribeAccount_MultipleWithBadAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, _, err := ExecuteCmd(createDescribeAccountCmd(), "--name", "C")
	require.Error(t, err)
}

func TestDescribeAccount_Interactive(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, _, err := ExecuteInteractiveCmd(createDescribeAccountCmd(), []interface{}{0})
	require.NoError(t, err)
}

func TestDescribeAccount_Latency(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", true)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	ac.Exports[0].Latency = &jwt.ServiceLatency{Sampling: 10, Results: "lat"}
	token, err := ac.Encode(ts.OperatorKey)
	require.NoError(t, err)
	_, err = ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)

	out, _, err := ExecuteInteractiveCmd(createDescribeAccountCmd(), []interface{}{0})
	require.NoError(t, err)
	require.Contains(t, out, "lat (10%)")
}

func TestDescribeAccount_Json(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	out, _, err := ExecuteCmd(rootCmd, "describe", "account", "--json")
	require.NoError(t, err)
	m := make(map[string]interface{})
	err = json.Unmarshal([]byte(out), &m)
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Subject, m["sub"])
}

func TestDescribeAccount_JsonPath(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	out, _, err := ExecuteCmd(rootCmd, "describe", "account", "--field", "sub")
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("\"%s\"\n", ac.Subject), out)
}

func TestDescribeAccount_JSTiers(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	ac.Limits.JetStreamTieredLimits = jwt.JetStreamTieredLimits{}
	ac.Limits.JetStreamTieredLimits["R1"] = jwt.JetStreamLimits{
		DiskStorage: 1024, Streams: 10, MaxBytesRequired: true, DiskMaxStreamBytes: 512}
	ac.Limits.JetStreamTieredLimits["R3"] = jwt.JetStreamLimits{
		MemoryStorage: 1024, Streams: 10, MaxBytesRequired: false,
		MemoryMaxStreamBytes: 512, MaxAckPending: 99}
	token, err := ac.Encode(ts.OperatorKey)
	require.NoError(t, err)
	_, err = ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)
	out, _, err := ExecuteInteractiveCmd(createDescribeAccountCmd(), []interface{}{0})
	require.NoError(t, err)
	require.Contains(t, out, " | R1")
	require.Contains(t, out, " | R3")
	require.Contains(t, out, " | required")
	require.Contains(t, out, " | optional")
	require.Contains(t, out, " | 99")
}

func TestDescribeAccount_Callout(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, uPK, _ := CreateUserKey(t)
	_, aPK, _ := CreateAccountKey(t)
	_, xPK, _ := CreateCurveKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(),
		"--auth-user", uPK,
		"--allowed-account", aPK,
		"--curve", xPK)
	require.NoError(t, err)

	out, _, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	require.Contains(t, out, fmt.Sprintf(" | %s", uPK))
	require.Contains(t, out, fmt.Sprintf(" | %s", aPK))
	require.Contains(t, out, fmt.Sprintf(" | %s", xPK))
}

func TestDescribeAccount_SubjectEncoding(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", true)

	out, _, err := ExecuteCmd(rootCmd, "describe", "account", "--json")
	require.NoError(t, err)
	require.Contains(t, out, "foo.>")
}
