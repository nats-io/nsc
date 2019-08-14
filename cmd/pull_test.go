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
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func editAccount(t *testing.T, kp nkeys.KeyPair, d []byte, tag string) []byte {
	ac, err := jwt.DecodeAccountClaims(string(d))
	require.NoError(t, err)
	ac.Tags.Add(tag)

	token, err := ac.Encode(kp)
	require.NoError(t, err)
	return []byte(token)
}

func Test_SyncAccount(t *testing.T) {
	// run a jwt account server
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	kp := ts.GetAccountKey(t, "A")
	pk, err := kp.PublicKey()
	require.NoError(t, err)

	d := editAccount(t, kp, m[pk], "test")
	m[pk] = d

	_, _, err = ExecuteCmd(createPullCmd())
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "test")
}

func Test_SyncMultipleAccount(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	kp := ts.GetAccountKey(t, "A")
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	d := editAccount(t, kp, m[pk], "test")
	m[pk] = d

	ts.AddAccount(t, "B")
	kp = ts.GetAccountKey(t, "B")
	pk, err = kp.PublicKey()
	require.NoError(t, err)
	d = editAccount(t, kp, m[pk], "test")
	m[pk] = d

	_, _, err = ExecuteCmd(createPullCmd(), "--all")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "test")

	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "test")
}

func Test_SyncNoAccountServer(t *testing.T) {
	ts := NewTestStore(t, "O")
	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(createPullCmd())
	require.Error(t, err)
}
