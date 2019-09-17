/*
 *
 *  * Copyright 2018-2019 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package cmd

import (
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_EditOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	tests := CmdTests{
		{createEditOperatorCmd(), []string{"edit", "operator"}, nil, []string{"specify an edit option"}, true},
		{createEditOperatorCmd(), []string{"edit", "operator", "--sk"}, nil, []string{"flag needs an argument"}, true},
		{createEditOperatorCmd(), []string{"edit", "operator", "--sk", "SAADOZRUTPZS6LIXS6CSSSW5GXY3DNMQMSDTVWHQNHQTIBPGNSADSMBPEU"}, nil, []string{"invalid operator signing key"}, true},
		{createEditOperatorCmd(), []string{"edit", "operator", "--sk", "OBMWGGURAFWMH3AFDX65TVIH4ZYSL7UKZ3LOH2ZRWIAU7PGZ3IJNR6W5"}, nil, []string{"edited operator"}, false},
		{createEditOperatorCmd(), []string{"edit", "operator", "--tag", "O", "--start", "2019-04-13", "--expiry", "2050-01-01"}, nil, []string{"edited operator"}, false},
	}

	tests.Run(t, "root", "edit")
}

func Test_EditOperatorSigningKeys(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	s1, pk1, _ := CreateOperatorKey(t)
	_, pk2, _ := CreateOperatorKey(t)

	_, _, err := ExecuteCmd(createEditOperatorCmd(), "--sk", pk1, "--sk", pk2)
	require.NoError(t, err)

	d, err := ts.Store.Read(store.JwtName("O"))
	require.NoError(t, err)

	oc, err := jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)

	require.Contains(t, oc.SigningKeys, pk1)
	require.Contains(t, oc.SigningKeys, pk2)

	_, _, err = ExecuteCmd(HoistRootFlags(CreateAddAccountCmd()), "--name", "A", "-K", string(s1))
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, oc.DidSign(ac))

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--rm-sk", pk1)
	require.NoError(t, err)

	d, err = ts.Store.Read(store.JwtName("O"))
	require.NoError(t, err)

	oc, err = jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)

	require.NotContains(t, oc.SigningKeys, pk1)
	require.Contains(t, oc.SigningKeys, pk2)
	require.False(t, oc.DidSign(ac))
}

func Test_EditOperatorServiceURLs(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	u1 := "nats://localhost:4222"
	u2 := "tls://localhost:4333"
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Len(t, oc.OperatorServiceURLs, 0)

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--service-url", u1, "--service-url", u2)
	require.NoError(t, err)

	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Contains(t, oc.OperatorServiceURLs, u1)
	require.Contains(t, oc.OperatorServiceURLs, u2)

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--rm-service-url", u1)
	require.NoError(t, err)
	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotContains(t, oc.OperatorServiceURLs, u1)
	require.Contains(t, oc.OperatorServiceURLs, u2)
}

func Test_EditOperatorServiceURLsInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	u1 := "nats://localhost:4222"
	u2 := "tls://localhost:4333"

	// valid from, valid until, add tags, acc jwt server, add service url, url, add another, url, add another, add signing key
	inputs := []interface{}{"0", "0", true, "xxx", false, "", true, u1, true, u2, false, false}

	_, _, err := ExecuteInteractiveCmd(createEditOperatorCmd(), inputs)
	require.NoError(t, err)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Contains(t, oc.OperatorServiceURLs, u1)
	require.Contains(t, oc.OperatorServiceURLs, u2)
	require.Contains(t, oc.Tags, "xxx")

	// valid from, valid until, acc jwt server, add service url, remove server urls, add signing key
	inputs = []interface{}{"0", "0", true, []int{0}, false, "", false, true, []int{0}, false}

	_, _, err = ExecuteInteractiveCmd(createEditOperatorCmd(), inputs)
	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotContains(t, oc.OperatorServiceURLs, u1)
	require.Contains(t, oc.OperatorServiceURLs, u2)
	require.NotContains(t, oc.Tags, "xxx")
}
