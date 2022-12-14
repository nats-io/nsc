/*
 * Copyright 2018-2022 The NATS Authors
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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"

	"github.com/nats-io/nsc/v2/cmd/store"
)

func Test_AddAccount(t *testing.T) {
	ts := NewTestStore(t, "add_account")
	defer ts.Done(t)

	_, bar, _ := CreateAccountKey(t)
	// a cluster key
	ckp, err := nkeys.CreateCluster()
	require.NoError(t, err)
	cpk, err := ckp.PublicKey()
	require.NoError(t, err)

	tests := CmdTests{
		{CreateAddAccountCmd(), []string{"add", "account"}, nil, []string{"account name is required"}, true},
		{CreateAddAccountCmd(), []string{"add", "account", "--name", "A"}, nil, []string{"generated and stored account key", "added account"}, false},
		{CreateAddAccountCmd(), []string{"add", "account", "--name", "A"}, nil, []string{"the account \"A\" already exists"}, true},
		{CreateAddAccountCmd(), []string{"add", "account", "--name", "B", "--public-key", bar}, nil, nil, false},
		{CreateAddAccountCmd(), []string{"add", "account", "--name", "*"}, nil, []string{"generated and stored account key", "added account"}, false},
		{CreateAddAccountCmd(), []string{"add", "account", "--name", "*"}, nil, []string{"generated and stored account key", "added account"}, false}, // should make a new name
		{CreateAddAccountCmd(), []string{"add", "account", "--name", "X", "--public-key", cpk}, nil, []string{"specified key is not a valid account nkey"}, true},
		{CreateAddAccountCmd(), []string{"add", "account", "--name", "badexp", "--expiry", "30d"}, nil, nil, false},
	}

	tests.Run(t, "root", "add")
}

func Test_AddAccountNoStore(t *testing.T) {
	// reset the store
	require.NoError(t, ForceStoreRoot(t, ""))
	_, _, err := ExecuteCmd(CreateAddAccountCmd())
	require.NotNil(t, err)
	require.Equal(t, "no stores available", err.Error())
}

func Test_AddAccountValidateOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "A", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)
	validateAddAccountClaims(t, ts)
	ts.List(t)
}

func Test_AddAccountInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	inputs := []interface{}{"A", true, "2018-01-01", "2050-01-01", 0}

	cmd := CreateAddAccountCmd()
	HoistRootFlags(cmd)
	_, _, err := ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)
	validateAddAccountClaims(t, ts)
}

func validateAddAccountClaims(t *testing.T, ts *TestStore) {
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	kp, err := ts.KeyStore.GetKeyPair(ac.Subject)
	require.NoError(t, err)
	_, err = kp.Seed()
	require.NoError(t, err, "stored key should be a seed")

	pub, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, ac.Subject, pub, "public key is subject")

	okp, err := ts.KeyStore.GetKeyPair(ac.Issuer)
	require.NoError(t, err)
	// operator stores will not return a keypair
	if okp == nil {
		okp = kp
	}

	oppub, err := okp.PublicKey()
	require.NoError(t, err, "getting public key for operator")
	require.Equal(t, ac.Issuer, oppub, "operator signed it")

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)
	require.Equal(t, start, ac.NotBefore)

	expire, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)
	require.Equal(t, expire, ac.Expires)
}

func Test_AddAccountManagedStore(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "A", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)
}

func Test_AddAccountManagedStoreWithSigningKey(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)
	_, pub, kp := CreateOperatorKey(t)
	oc := jwt.NewOperatorClaims(pub)
	oc.Name = "O"
	s1, psk, sk := CreateOperatorKey(t)
	ts.KeyStore.Store(sk)
	oc.SigningKeys.Add(psk)
	token, err := oc.Encode(kp)
	require.NoError(t, err)
	tf := filepath.Join(ts.Dir, "O.jwt")
	err = Write(tf, []byte(token))
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", tf)
	require.NoError(t, err)
	// sign with the signing key
	inputs := []interface{}{"A", true, "0", "0", 0, string(s1)}
	_, _, err = ExecuteInteractiveCmd(HoistRootFlags(CreateAddAccountCmd()), inputs)
	require.NoError(t, err)
	accJWT, err := os.ReadFile(filepath.Join(ts.StoreDir, "O", "accounts", "A", "A.jwt"))
	require.NoError(t, err)
	ac, err := jwt.DecodeAccountClaims(string(accJWT))
	require.NoError(t, err)
	require.False(t, ac.IsSelfSigned())
	require.Equal(t, ac.Issuer, psk)
	require.True(t, oc.DidSign(ac))
	// sign with the account key
	inputs = []interface{}{"B", true, "0", "0", 1, string(s1)}
	_, _, err = ExecuteInteractiveCmd(HoistRootFlags(CreateAddAccountCmd()), inputs)
	require.NoError(t, err)
	accJWT, err = os.ReadFile(filepath.Join(ts.StoreDir, "O", "accounts", "B", "B.jwt"))
	require.NoError(t, err)
	ac, err = jwt.DecodeAccountClaims(string(accJWT))
	require.NoError(t, err)
	require.True(t, ac.IsSelfSigned())
	require.False(t, oc.DidSign(ac))
}

func Test_AddAccountInteractiveSigningKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	s1, pk1, _ := CreateOperatorKey(t)
	_, _, err := ExecuteCmd(createEditOperatorCmd(), "--sk", pk1)
	require.NoError(t, err)

	// sign with the custom key
	inputs := []interface{}{"A", true, "0", "0", 1, string(s1)}
	_, _, err = ExecuteInteractiveCmd(HoistRootFlags(CreateAddAccountCmd()), inputs)
	require.NoError(t, err)

	d, err := ts.Store.Read(store.JwtName("O"))
	require.NoError(t, err)
	oc, err := jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Issuer, pk1)
	require.True(t, oc.DidSign(ac))
	require.Equal(t, pk1, ac.Issuer)
}

func Test_AddAccountNameArg(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(HoistRootFlags(CreateAddAccountCmd()), "A")
	require.NoError(t, err)

	_, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
}

func Test_AddAccountWithExistingKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	kp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)
	pk, err := kp.PublicKey()
	require.NoError(t, err)

	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "A", "--public-key", pk)
	require.NoError(t, err)
}

func Test_AddManagedAccountWithExistingKey(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	kp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)
	pk, err := kp.PublicKey()
	require.NoError(t, err)

	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "A", "--public-key", pk)
	require.NoError(t, err)

	// inspect the pushed JWT before it was resigned
	ac, err := jwt.DecodeAccountClaims(string(m[fmt.Sprintf("SRC_%s", pk)]))
	require.NoError(t, err)
	require.Equal(t, pk, ac.Subject)
	require.Equal(t, pk, ac.Issuer)
}

func Test_AddAccountWithSigningKeyOnly(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	kp, err := nkeys.CreateOperator()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	require.True(t, ts.KeyStore.HasPrivateKey(pk))

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--sk", pk)
	require.NoError(t, err)
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)
	require.NoError(t, ts.KeyStore.Remove(oc.Subject))
	require.False(t, ts.KeyStore.HasPrivateKey(oc.Subject))

	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "A")
	require.NoError(t, err)

	_, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
}

func Test_AddAccount_Pubs(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "-n", "A", "--allow-pub", "a,b", "--allow-pubsub", "c", "--deny-pub", "foo", "--deny-pubsub", "bar")
	require.NoError(t, err)

	cc, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Allow, []string{"a", "b", "c"})
	require.ElementsMatch(t, cc.DefaultPermissions.Sub.Allow, []string{"c"})
	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Deny, []string{"foo", "bar"})
	require.ElementsMatch(t, cc.DefaultPermissions.Sub.Deny, []string{"bar"})
}
