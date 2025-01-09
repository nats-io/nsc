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
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func Test_ValidateNoOperator(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)
	storeDir := ts.AddSubDir(t, "stores")
	require.DirExists(t, storeDir)
	_, err := ExecuteCmd(createValidateCommand(), []string{}...)
	require.Error(t, err)
	t.Log(err.Error())
	require.True(t, strings.Contains(err.Error(), "set an operator") ||
		strings.Contains(err.Error(), "no such file or directory"))
}

func Test_ValidateNoAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	out, err := ExecuteCmd(createValidateCommand())
	require.NoError(t, err)
	require.Contains(t, out.Out, "Operator \"O\"")
	require.Contains(t, out.Out, "No issues found")
}

func Test_ValidateExpiredOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	before, err := ParseExpiry("1999-12-01")
	require.NoError(t, err)
	oc.Expires = before

	token, err := oc.Encode(ts.OperatorKey)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	out, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, out.Out, "claim is expired")
}

func Test_ValidateBadOperatorIssuer(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	_, _, kp := CreateOperatorKey(t)
	token, err := oc.Encode(kp)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	out, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, out.Out, "not issued by operator")
}

func Test_ExpiredAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	before, err := ParseExpiry("1999-12-01")
	require.NoError(t, err)
	ac.Expires = before
	token, err := ac.Encode(ts.OperatorKey)
	require.NoError(t, err)
	rs, err := ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)
	require.Nil(t, rs)

	out, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, out.Out, "claim is expired")
}

func Test_ValidateBadAccountIssuer(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	_, _, kp := CreateOperatorKey(t)
	token, err := ac.Encode(kp)
	require.NoError(t, err)
	rs, err := ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)
	require.Nil(t, rs)

	out, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, out.Out, "not issued by operator")
}

func Test_ValidateBadUserIssuer(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)

	_, _, kp := CreateAccountKey(t)
	token, err := uc.Encode(kp)
	require.NoError(t, err)
	fp := filepath.Join(ts.StoreDir, "O", store.Accounts, "A", store.Users, store.JwtName("U"))
	require.NoError(t, os.Remove(fp))
	require.NoError(t, WriteFile(fp, []byte(token)))

	out, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, out.Out, "not issued by account")
}

func Test_ValidateExpiredUser(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	before, err := ParseExpiry("1999-12-01")
	require.NoError(t, err)
	uc.Expires = before
	kp := ts.GetAccountKey(t, "A")
	token, err := uc.Encode(kp)
	require.NoError(t, err)
	rs, err := ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)
	require.Nil(t, rs)

	out, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, out.Out, "user \"U\": claim is expired")
}

func Test_ValidateOneOfAccountOrAll(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	out, err := ExecuteCmd(createValidateCommand(), []string{"--account", "A", "--all-accounts"}...)
	require.Error(t, err)
	require.Contains(t, out.Err, "specify only one")
}

func Test_ValidateBadAccountName(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	out, err := ExecuteCmd(createValidateCommand(), []string{"--account", "B"}...)
	require.Error(t, err)
	require.Contains(t, out.Err, "not in accounts for operator")
}

func Test_ValidateInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	out, err := ExecuteInteractiveCmd(HoistRootFlags(createValidateCommand()), []interface{}{1}, []string{"--account", "B"}...)
	require.NoError(t, err)
	require.Contains(t, out.Out, "Account \"B\"")
}

func Test_ValidateJsSys(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "SYS")
	_, err := ExecuteCmd(createEditOperatorCmd(), "--system-account", "SYS")
	require.NoError(t, err)

	sys, err := ts.Store.ReadAccountClaim("SYS")
	require.NoError(t, err)
	require.False(t, sys.Limits.IsJSEnabled())

	sys.Limits.JetStreamTieredLimits = make(map[string]jwt.JetStreamLimits)
	sys.Limits.JetStreamTieredLimits["R1"] = jwt.JetStreamLimits{DiskStorage: -1, MemoryStorage: -1}

	okp, err := ts.KeyStore.GetKeyPair(ts.GetOperatorPublicKey(t))
	require.NoError(t, err)
	token, err := sys.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	out, err := ExecuteInteractiveCmd(HoistRootFlags(createValidateCommand()), []interface{}{1}, []string{}...)
	require.Error(t, err)
	require.Contains(t, out.Out, "JetStream should not be enabled for system account")
}
