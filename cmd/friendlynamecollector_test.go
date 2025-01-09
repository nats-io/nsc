// Copyright 2018-2019 The NATS Authors
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
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_FriendlyNameFilter(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	fn, err := friendlyNameFilter()
	require.NoError(t, err)
	require.Equal(t, "O", fn(oc.Subject))
	require.Equal(t, "XXX", fn("XXX"))

}

func Test_FriendlyNameCollector(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	okp, err := ts.KeyStore.GetKeyPair(oc.Subject)
	require.NoError(t, err)

	_, ok2, okp2 := CreateOperatorKey(t)
	oc.SigningKeys.Add(ok2)
	token, err := oc.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	aac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	_, ak2, _ := CreateAccountKey(t)
	aac.SigningKeys.Add(ak2)
	token, err = aac.Encode(okp2)
	require.NoError(t, err)
	rs, err := ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)
	require.Nil(t, rs)

	bac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)

	// force fully qualifiying all names
	m, err := friendlyNames("")
	require.NoError(t, err)
	require.Len(t, m, 5)
	require.Equal(t, "O", m[oc.Subject])
	require.Equal(t, "O", m[oc.SigningKeys[0]])
	require.Equal(t, "A", m[aac.Subject])
	require.Equal(t, "A", m[aac.SigningKeys.Keys()[0]])
	require.Equal(t, "B", m[bac.Subject])

	ts.AddOperator(t, "OO")
	ooc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	oopk := ooc.Subject
	ts.AddAccount(t, "X")
	xc, err := ts.Store.ReadAccountClaim("X")
	require.NoError(t, err)
	xpk := xc.Subject

	m, err = friendlyNames("OO")
	require.NoError(t, err)
	require.Len(t, m, 7)
	require.Equal(t, "OO", m[oopk])
	require.Equal(t, "X", m[xpk])
	require.Equal(t, "O", m[oc.Subject])
	require.Equal(t, "O", m[oc.SigningKeys[0]])
	require.Equal(t, "O/A", m[aac.Subject])
	require.Equal(t, "O/A", m[aac.SigningKeys.Keys()[0]])
	require.Equal(t, "O/B", m[bac.Subject])
}
