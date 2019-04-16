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
		{createEditOperator(), []string{"edit", "operator"}, nil, []string{"specify an edit option"}, true},
		{createEditOperator(), []string{"edit", "operator", "--expiry", "2018-01-01"}, nil, []string{"expiry \"2018-01-01\" is in the past"}, true},
		{createEditOperator(), []string{"edit", "operator", "--sk"}, nil, []string{"flag needs an argument"}, true},
		{createEditOperator(), []string{"edit", "operator", "--sk", "SAADOZRUTPZS6LIXS6CSSSW5GXY3DNMQMSDTVWHQNHQTIBPGNSADSMBPEU"}, nil, []string{"invalid operator signing key"}, true},
		{createEditOperator(), []string{"edit", "operator", "--sk", "OBMWGGURAFWMH3AFDX65TVIH4ZYSL7UKZ3LOH2ZRWIAU7PGZ3IJNR6W5"}, nil, []string{"edited operator"}, false},
		{createEditOperator(), []string{"edit", "operator", "--tag", "O", "--start", "2019-04-13", "--expiry", "2050-01-01"}, nil, []string{"edited operator"}, false},
	}

	tests.Run(t, "root", "edit")
}

func Test_EditOperatorSigningKeys(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	s1, pk1, _ := CreateOperatorKey(t)
	_, pk2, _ := CreateOperatorKey(t)

	_, _, err := ExecuteCmd(createEditOperator(), "--sk", pk1, "--sk", pk2)
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

	_, _, err = ExecuteCmd(createEditOperator(), "--rm-sk", pk1)
	require.NoError(t, err)

	d, err = ts.Store.Read(store.JwtName("O"))
	require.NoError(t, err)

	oc, err = jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)

	require.NotContains(t, oc.SigningKeys, pk1)
	require.Contains(t, oc.SigningKeys, pk2)
	require.False(t, oc.DidSign(ac))
}
