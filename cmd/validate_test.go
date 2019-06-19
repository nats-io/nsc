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
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_ValidateNoOperator(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)
	storeDir := filepath.Join(ts.Dir, "store")
	require.NoError(t, os.Mkdir(storeDir, 0777))
	require.DirExists(t, storeDir)

	_, _, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, err.Error(), "set an operator")
}

func Test_ValidateNoAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, stderr, err := ExecuteCmd(createValidateCommand())
	require.NoError(t, err)
	require.Contains(t, stderr, "Operator \"O\"")
	require.Contains(t, stderr, "No issues found")
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
	require.NoError(t, ts.Store.StoreClaim([]byte(token)))

	_, stderr, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, stderr, "claim is expired")
}

func Test_ValidateBadOperatorIssuer(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	_, _, kp := CreateOperatorKey(t)
	token, err := oc.Encode(kp)
	require.NoError(t, ts.Store.StoreClaim([]byte(token)))

	_, stderr, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, stderr, "not issued by operator")
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
	require.NoError(t, ts.Store.StoreClaim([]byte(token)))

	_, stderr, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, stderr, "claim is expired")
}

func Test_ValidateBadAccountIssuer(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	_, _, kp := CreateOperatorKey(t)
	token, err := ac.Encode(kp)
	require.NoError(t, ts.Store.StoreClaim([]byte(token)))

	_, stderr, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, stderr, "not issued by operator")
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
	fp := filepath.Join(ts.Dir, "store", "O", store.Accounts, "A", store.Users, store.JwtName("U"))
	require.NoError(t, os.Remove(fp))
	require.NoError(t, Write(fp, []byte(token)))

	_, stderr, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, stderr, "not issued by account")
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
	kp, err := ts.GetAccountKey(t, "A")
	token, err := uc.Encode(kp)
	require.NoError(t, ts.Store.StoreClaim([]byte(token)))

	_, stderr, err := ExecuteCmd(createValidateCommand())
	require.Error(t, err)
	require.Contains(t, stderr, "user \"U\": claim is expired")
}

func Test_ValidateOneOfAccountOrAll(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, stderr, err := ExecuteCmd(createValidateCommand(), "--account", "A", "--all-accounts")
	require.Error(t, err)
	require.Contains(t, stderr, "specify only one")
}

func Test_ValidateBadAccountName(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, stderr, err := ExecuteCmd(createValidateCommand(), "--account", "B")
	require.Error(t, err)
	require.Contains(t, stderr, "not in accounts for operator")
}

func Test_ValidateInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, stderr, err := ExecuteInteractiveCmd(HoistRootFlags(createValidateCommand()), []interface{}{1}, "--account", "B")
	require.NoError(t, err)
	require.Contains(t, stderr, "Account \"B\"")
}
