/*
 * Copyright 2018-2025 The NATS Authors
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
	"github.com/nats-io/nkeys"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func TestDescribeAccount_Single(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	opub := ts.GetOperatorPublicKey(t)

	ts.AddAccount(t, "A")
	pub := ts.GetAccountPublicKey(t, "A")

	out, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	// account A public key
	require.Contains(t, out.Out, pub)
	// operator public key
	require.Contains(t, out.Out, opub)
	// name for the account
	require.Contains(t, out.Out, " A ")
}

func TestDescribeAccountRaw(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	Raw = true
	out, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)

	ac, err := jwt.DecodeAccountClaims(out.Out)
	require.NoError(t, err)

	require.NotNil(t, ac)
	require.Equal(t, "A", ac.Name)
}

func TestDescribeAccount_Multiple(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	out, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	require.Contains(t, StripTableDecorations(out.Out), "Name B")
}

func TestDescribeAccount_MultipleAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	require.NoError(t, GetConfig().SetAccount(""))

	_, err := ExecuteCmd(createDescribeAccountCmd(), []string{}...)
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

	out, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	require.Contains(t, out.Out, pub)
	require.Contains(t, out.Out, opub)
	require.Contains(t, out.Out, " B ")
}

func TestDescribeAccount_MultipleWithFlag(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	pub := ts.GetAccountPublicKey(t, "B")

	out, err := ExecuteCmd(createDescribeAccountCmd(), "--name", "B")
	require.NoError(t, err)
	require.Contains(t, out.Out, pub)
	require.Contains(t, out.Out, " B ")
}

func TestDescribeAccount_MultipleWithBadAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, err := ExecuteCmd(createDescribeAccountCmd(), []string{"--name", "C"}...)
	require.Error(t, err)
}

func TestDescribeAccount_Interactive(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, err := ExecuteInteractiveCmd(createDescribeAccountCmd(), []interface{}{0})
	require.NoError(t, err)
}

func TestDescribeAccount_Latency(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "q", 0, true)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	ac.Exports[0].Latency = &jwt.ServiceLatency{Sampling: 10, Results: "lat"}
	token, err := ac.Encode(ts.OperatorKey)
	require.NoError(t, err)
	_, err = ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)

	out, err := ExecuteInteractiveCmd(createDescribeAccountCmd(), []interface{}{0}, []string{}...)
	require.NoError(t, err)
	require.Contains(t, out.Out, "lat (10%)")
}

func TestDescribeAccount_Json(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	out, err := ExecuteCmd(rootCmd, "describe", "account", "--json")
	require.NoError(t, err)
	m := make(map[string]interface{})
	err = json.Unmarshal([]byte(out.Out), &m)
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Subject, m["sub"])
}

func TestDescribeAccount_JsonPath(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	out, err := ExecuteCmd(rootCmd, "describe", "account", "--field", "sub")
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("\"%s\"\n", ac.Subject), out.Out)
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
	out, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	require.Contains(t, out.Out, " | R1")
	require.Contains(t, out.Out, " | R3")
	require.Contains(t, out.Out, " | required")
	require.Contains(t, out.Out, " | optional")
	require.Contains(t, out.Out, " | 99")
}

func TestDescribeAccount_Callout(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, uPK, _ := CreateUserKey(t)
	_, aPK, _ := CreateAccountKey(t)
	_, xPK, _ := CreateCurveKey(t)
	_, err := ExecuteCmd(createEditAuthorizationCallout(),
		"--auth-user", uPK,
		"--allowed-account", aPK,
		"--curve", xPK)
	require.NoError(t, err)

	out, err := ExecuteCmd(createDescribeAccountCmd())
	require.NoError(t, err)
	require.Contains(t, out.Out, fmt.Sprintf(" | %s", uPK))
	require.Contains(t, out.Out, fmt.Sprintf(" | %s", aPK))
	require.Contains(t, out.Out, fmt.Sprintf(" | %s", xPK))
}

func TestDescribeAccount_SubjectEncoding(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.>", 0, true)

	out, err := ExecuteCmd(rootCmd, "describe", "account", "--json")
	require.NoError(t, err)
	require.Contains(t, out.Out, "foo.>")
}

func TestDescribeAccount_Output(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	p := filepath.Join(ts.Dir, "A.json")
	_, err := ExecuteCmd(rootCmd, []string{"describe", "account", "--json", "--output-file", p}...)
	require.NoError(t, err)
	data, err := os.ReadFile(p)
	require.NoError(t, err)

	ac := jwt.AccountClaims{}
	require.NoError(t, json.Unmarshal(data, &ac))
	require.Equal(t, "A", ac.Name)

	p = filepath.Join(ts.Dir, "A.txt")
	_, err = ExecuteCmd(rootCmd, []string{"describe", "account", "--output-file", p}...)
	require.NoError(t, err)
	data, err = os.ReadFile(p)
	require.NoError(t, err)
	strings.Contains(string(data), "Account Details")

	p = filepath.Join(ts.Dir, "A.jwt")
	_, err = ExecuteCmd(rootCmd, []string{"describe", "account", "--raw", "--output-file", p}...)
	require.NoError(t, err)
	data, err = os.ReadFile(p)
	require.NoError(t, err)
	require.Contains(t, string(data), "-----BEGIN NATS ACCOUNT JWT-----\ney")
}

func TestDescribeAccount_Exports(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "foo.bar.*.>", 0, true)

	out, err := ExecuteCmd(rootCmd, "describe", "account")
	require.NoError(t, err)
	require.Contains(t, out.Out, "| Account Token Position |")
	require.Contains(t, out.Out, "foo.bar.*.> | -")

	ts.AddAccount(t, "B")
	ts.AddExport(t, "B", jwt.Stream, "foo.bar.*.>", 3, true)

	out, err = ExecuteCmd(rootCmd, "describe", "account", "-n", "B")
	require.NoError(t, err)
	require.Contains(t, out.Out, "| Account Token Position |")
	require.Contains(t, out.Out, "foo.bar.*.> | 3")
}

func TestDescribeAccountMore(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	ac.Description = "hello"
	ac.InfoURL = "https://example.com"
	_, signingKey, _ := CreateAccountKey(t)
	ac.SigningKeys.Add(signingKey)

	_, issuer, _ := CreateAccountKey(t)
	scope := jwt.NewUserScope()
	scope.Key = issuer
	scope.Role = "nothing"
	scope.Description = "no permissions"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Sub: jwt.Permission{Deny: []string{">"}},
			Pub: jwt.Permission{Deny: []string{">"}},
		},
	}
	ac.SigningKeys.AddScopedSigner(scope)

	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{DiskStorage: -1, MemoryStorage: -1}
	ac.Limits.LeafNodeConn = 1

	_, user, _ := CreateUserKey(t)
	ac.Revocations = jwt.RevocationList{}
	ac.Revocations.Revoke(user, time.Now())

	ac.Trace = &jwt.MsgTrace{
		Destination: "foo",
		Sampling:    100,
	}

	ekp, err := nkeys.CreateUser()
	require.NoError(t, err)
	a, err := ekp.PublicKey()
	require.NoError(t, err)
	ac.Imports.Add(&jwt.Import{
		Name:         "hello",
		Subject:      "bar.>",
		LocalSubject: "fromA.>",
		Type:         jwt.Stream,
		AllowTrace:   true,
		Share:        true,
		Account:      a,
	})

	ac.Mappings = make(map[jwt.Subject][]jwt.WeightedMapping)
	ac.Mappings["mapfoo"] = []jwt.WeightedMapping{{Subject: "map.>", Weight: 20, Cluster: "a"}}

	token, err := ac.Encode(ts.OperatorKey)
	require.NoError(t, err)
	_, err = ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)

	out, err := ExecuteCmd(rootCmd, "describe", "account", "-n", "A")
	require.NoError(t, err)

	stdout := StripMultipleSpaces(out.Out)
	require.Contains(t, stdout, "| Description | hello")
	require.Contains(t, stdout, "| Info Url | https://example.com")
	// order of the key may be unexpected, just find the key
	require.Contains(t, stdout, signingKey)
	require.Contains(t, stdout, "| Max Disk Storage | Unlimited")
	require.Contains(t, stdout, "| Max Mem Storage | Unlimited")
	require.Contains(t, stdout, "| Max Leaf Node Connections | 1")
	require.Contains(t, stdout, "| Revocations | 1")
	require.Contains(t, stdout, "| Subject | foo")
	require.Contains(t, stdout, "| Sampling | 100%")
	require.Contains(t, stdout, "| hello | Stream | bar.> | fromA.>")
	require.Contains(t, stdout, "| mapfoo | map.> | 20")

	require.Contains(t, stdout, "| Key | "+issuer)
	require.Contains(t, stdout, "| Role | nothing")
	require.Contains(t, stdout, "| Description | no permissions")
}
