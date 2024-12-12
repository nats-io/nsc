/*
 * Copyright 2020 The NATS Authors
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
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ReIssue(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	op1, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createReIssueOperatorCmd())
	require.NoError(t, err)
	op2, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotEqual(t, op1.Subject, op2.Subject)
	require.Len(t, op1.SigningKeys, 0)
	// add testing account
	ts.AddAccount(t, "A")

	_, stderr, err := ExecuteCmd(createReIssueOperatorCmd(), "--convert-to-signing-key")
	require.NoError(t, err)
	op3, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotEqual(t, op2.Subject, op3.Subject)
	require.Equal(
		t,
		stderr,
		"[ OK ] operator \"O\" successfully changed identity to: "+op3.Subject+"\n"+
			"[ OK ] old operator key \""+op2.Subject+"\" turned into signing key\n"+
			"all jobs succeeded\n",
	)
	require.Len(t, op3.SigningKeys, 1)
	require.True(t, op3.SigningKeys.Contains(op2.Subject))

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, op3.DidSign(ac))

	_, _, err = ExecuteCmd(createReIssueOperatorCmd(), "--name", "O")
	require.NoError(t, err)
	op4, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotEqual(t, op3.Subject, op4.Subject)
	require.Len(t, op4.SigningKeys, 1)
	require.True(t, op4.SigningKeys.Contains(op2.Subject))

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, op4.DidSign(ac))
}

func Test_ReIssueWithKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	op1, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	// add testing account
	ts.AddAccount(t, "A")
	ac1, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, op1.DidSign(ac1))

	seed, pub, _ := CreateOperatorKey(t)

	cmd := createReIssueOperatorCmd()
	HoistRootFlags(cmd)
	_, stderr, err := ExecuteCmd(cmd, "-K", string(seed))
	require.NoError(t, err)
	op2, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotEqual(t, op1.Subject, op2.Subject)
	require.Equal(t, pub, op2.Subject)
	require.Equal(
		t,
		stderr,
		"[ OK ] operator \"O\" successfully changed identity to: "+pub+"\n"+
			"[ OK ] account \"A\" re-signed\n"+
			"all jobs succeeded\n",
	)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, op2.DidSign(ac))
}

func Test_ReIssueStrict(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	op1, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	// add testing account
	ts.AddAccount(t, "A")

	_, _, err = ExecuteCmd(createReIssueOperatorCmd(), "--convert-to-signing-key")
	require.NoError(t, err)
	op3, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotEqual(t, op1.Subject, op3.Subject)
	require.Len(t, op3.SigningKeys, 1)
	require.True(t, op3.SigningKeys.Contains(op1.Subject))
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, op3.DidSign(ac))

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--require-signing-keys")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createReIssueOperatorCmd(), "--convert-to-signing-key")
	require.NoError(t, err)
}
