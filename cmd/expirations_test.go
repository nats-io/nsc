// Copyright 2018-2025 The NATS Authors
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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_ExpirationsNone(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	stdout, err := ExecuteCmd(createExpirationsCommand(), "--json")
	require.NoError(t, err)

	var expirations ExpirationReportJSON
	err = json.Unmarshal([]byte(stdout.Out), &expirations)
	require.NoError(t, err)
	_, err = time.Parse(time.RFC3339, expirations.ExpirationThreshold)
	require.NoError(t, err)
	require.Len(t, expirations.Report, 4)
}

func Test_ExpirationsOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	// an hour ago
	oc.Expires = time.Now().Add(-time.Hour).UTC().Unix()
	token, err := oc.Encode(ts.OperatorKey)
	require.NoError(t, err)
	err = ts.Store.StoreRaw([]byte(token))
	require.NoError(t, err)

	stdout, err := ExecuteCmd(createExpirationsCommand(), []string{"--json"}...)
	require.NoError(t, err)

	var expirations ExpirationReportJSON
	err = json.Unmarshal([]byte(stdout.Out), &expirations)
	require.NoError(t, err)
	require.Len(t, expirations.Report, 1)
	require.True(t, expirations.Report[0].Expired)
}

func Test_ExpirationAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	ac.Expires = time.Now().Add(-time.Minute).UTC().Unix()
	token, err := ac.Encode(ts.GetAccountKey(t, "A"))
	require.NoError(t, err)
	err = ts.Store.StoreRaw([]byte(token))
	require.NoError(t, err)

	out, err := ExecuteCmd(createExpirationsCommand(), []string{"--json"}...)
	require.NoError(t, err)

	var expirations ExpirationReportJSON
	err = json.Unmarshal([]byte(out.Out), &expirations)
	require.NoError(t, err)
	require.Len(t, expirations.Report, 2)
	require.False(t, expirations.Report[0].Expired)
	require.True(t, expirations.Report[1].Expired)
}

func Test_ExpirationUser(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	uc.Expires = time.Now().Add(-time.Minute).UTC().Unix()
	token, err := uc.Encode(ts.GetAccountKey(t, "A"))
	require.NoError(t, err)
	err = ts.Store.StoreRaw([]byte(token))
	require.NoError(t, err)

	out, err := ExecuteCmd(createExpirationsCommand(), []string{"--json"}...)
	require.NoError(t, err)

	var expirations ExpirationReportJSON
	err = json.Unmarshal([]byte(out.Out), &expirations)
	require.NoError(t, err)
	require.Len(t, expirations.Report, 4)
	require.False(t, expirations.Report[0].Expired)
	require.False(t, expirations.Report[1].Expired)
	require.True(t, expirations.Report[2].Expired)
	// we didn't update the creds
	require.False(t, expirations.Report[3].Expired)
}

func Test_ExpiresSoonOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	// an hour ago
	oc.Expires = time.Now().Add(time.Hour * 24 * 7).UTC().Unix()
	token, err := oc.Encode(ts.OperatorKey)
	require.NoError(t, err)
	err = ts.Store.StoreRaw([]byte(token))
	require.NoError(t, err)

	out, err := ExecuteCmd(createExpirationsCommand(), []string{"--json"}...)
	require.NoError(t, err)

	var expirations ExpirationReportJSON
	err = json.Unmarshal([]byte(out.Out), &expirations)
	require.NoError(t, err)
	require.Len(t, expirations.Report, 1)
	require.False(t, expirations.Report[0].Expired)
	require.True(t, expirations.Report[0].ExpiresSoon)
}

func Test_ExpiresSoonAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	ac.Expires = time.Now().Add(time.Minute * 2).UTC().Unix()
	token, err := ac.Encode(ts.GetAccountKey(t, "A"))
	require.NoError(t, err)
	err = ts.Store.StoreRaw([]byte(token))
	require.NoError(t, err)

	out, err := ExecuteCmd(createExpirationsCommand(), []string{"--json"}...)
	require.NoError(t, err)

	var expirations ExpirationReportJSON
	err = json.Unmarshal([]byte(out.Out), &expirations)
	require.NoError(t, err)
	require.Len(t, expirations.Report, 2)
	require.False(t, expirations.Report[0].Expired)
	require.False(t, expirations.Report[1].Expired)
	require.True(t, expirations.Report[1].ExpiresSoon)
}

func Test_ExpiresSoonUser(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	uc.Expires = time.Now().Add(time.Hour).UTC().Unix()
	token, err := uc.Encode(ts.GetAccountKey(t, "A"))
	require.NoError(t, err)
	err = ts.Store.StoreRaw([]byte(token))
	require.NoError(t, err)

	creds, err := GenerateConfig(ts.Store, "A", "U", ts.GetUserKey(t, "A", "U"))
	require.NoError(t, err)
	_, err = ts.KeyStore.MaybeStoreUserCreds("A", "U", creds)
	require.NoError(t, err)

	out, err := ExecuteCmd(createExpirationsCommand(), []string{"--json"}...)
	require.NoError(t, err)

	var expirations ExpirationReportJSON
	err = json.Unmarshal([]byte(out.Out), &expirations)
	require.NoError(t, err)
	require.Len(t, expirations.Report, 4)
	require.False(t, expirations.Report[0].Expired)
	require.False(t, expirations.Report[1].Expired)
	require.False(t, expirations.Report[2].Expired)
	require.True(t, expirations.Report[2].ExpiresSoon)
	require.False(t, expirations.Report[3].Expired)
	require.True(t, expirations.Report[3].ExpiresSoon)
	require.False(t, expirations.Report[3].Expired)

	out, err = ExecuteCmd(createExpirationsCommand(), []string{"--skip", "--json"}...)
	require.NoError(t, err)
	err = json.Unmarshal([]byte(out.Out), &expirations)
	require.NoError(t, err)
	require.Len(t, expirations.Report, 2)
	require.Equal(t, expirations.Report[0].ID, uc.Subject)
	require.True(t, expirations.Report[0].ExpiresSoon)
	require.False(t, expirations.Report[0].Expired)
	require.Equal(t, expirations.Report[1].ID, uc.Subject)
	require.True(t, expirations.Report[1].ExpiresSoon)
	require.False(t, expirations.Report[1].Expired)
}

func Test_ExpirationsTable(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	uc.Expires = time.Now().Add(time.Hour).UTC().Unix()
	token, err := uc.Encode(ts.GetAccountKey(t, "A"))
	require.NoError(t, err)
	err = ts.Store.StoreRaw([]byte(token))
	require.NoError(t, err)

	out, err := ExecuteCmd(createExpirationsCommand())
	require.NoError(t, err)

	require.Contains(t, out.Out, "| O")
	require.Contains(t, out.Out, "| O/A")
	require.Contains(t, out.Out, "| Soon    | O/A/U")
	require.Contains(t, out.Out, "In 59 Minutes |")
	require.Contains(t, out.Out, filepath.FromSlash("creds/O/A/U.creds"))
}
