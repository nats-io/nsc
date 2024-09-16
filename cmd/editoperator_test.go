/*
 * Copyright 2018-2023 The NATS Authors
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
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_EditOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "TEST")

	tests := CmdTests{
		{createEditOperatorCmd(), []string{"edit", "operator"}, nil, []string{"specify an edit option"}, true},
		{createEditOperatorCmd(), []string{"edit", "operator", "--system-account", "ABTFVAXATJEOKIBESJ3LO3JTAAMDCZ755DLAAGGSDMH5TU6HSFL7YNYY"}, nil, []string{"set system account"}, false},
		{createEditOperatorCmd(), []string{"edit", "operator", "--system-account", "TEST"}, nil, []string{"set system account"}, false},
		{createEditOperatorCmd(), []string{"edit", "operator", "--system-account", "DOESNOTEXIST"}, nil, []string{"account DOESNOTEXIST does not exist in the current operator"}, true},
		{createEditOperatorCmd(), []string{"edit", "operator", "--sk"}, nil, []string{"flag needs an argument"}, true},
		{createEditOperatorCmd(), []string{"edit", "operator", "--sk", "SAADOZRUTPZS6LIXS6CSSSW5GXY3DNMQMSDTVWHQNHQTIBPGNSADSMBPEU"}, nil, []string{"invalid operator signing key"}, true},
		{createEditOperatorCmd(), []string{"edit", "operator", "--sk", "OBMWGGURAFWMH3AFDX65TVIH4ZYSL7UKZ3LOH2ZRWIAU7PGZ3IJNR6W5"}, nil, []string{"edited operator"}, false},
		{createEditOperatorCmd(), []string{"edit", "operator", "--tag", "O", "--start", "2019-04-13", "--expiry", "2050-01-01"}, nil, []string{"edited operator"}, false},
		{createEditOperatorCmd(), []string{"edit", "operator", "--require-signing-keys"}, nil, []string{"needs to be issued with a signing key first"}, true},
	}

	tests.Run(t, "root", "edit")
}

func readJWT(t *testing.T, elem ...string) string {
	t.Helper()
	fp := filepath.Join(elem...)
	require.FileExists(t, fp)
	theJWT, err := os.ReadFile(fp)
	require.NoError(t, err)
	return string(theJWT)
}

func checkAcc(t *testing.T, ts *TestStore, acc string) {
	t.Helper()
	opJWT := readJWT(t, ts.StoreDir, "O", "O.jwt")
	op, err := jwt.DecodeOperatorClaims(opJWT)
	require.NoError(t, err)
	require.True(t, op.StrictSigningKeyUsage)
	accJWT := readJWT(t, ts.StoreDir, "O", "accounts", acc, fmt.Sprintf("%s.jwt", acc))
	ac, err := jwt.DecodeAccountClaims(accJWT)
	require.NoError(t, err)
	require.NotEqual(t, ac.Issuer, op.Subject)
	require.Equal(t, ac.Issuer, op.SigningKeys[0])
	_, _, err = ExecuteCmd(createValidateCommand(), "--all-accounts")
	require.NoError(t, err)
}

func checkUsr(t *testing.T, ts *TestStore, acc string) {
	t.Helper()
	opJWT := readJWT(t, ts.StoreDir, "O", "O.jwt")
	op, err := jwt.DecodeOperatorClaims(opJWT)
	require.NoError(t, err)
	require.True(t, op.StrictSigningKeyUsage)
	accJWT := readJWT(t, ts.StoreDir, "O", "accounts", acc, fmt.Sprintf("%s.jwt", acc))
	ac, err := jwt.DecodeAccountClaims(accJWT)
	require.NoError(t, err)
	require.NotEqual(t, ac.Issuer, op.Subject)
	require.Equal(t, ac.Issuer, op.SigningKeys[0])
	usrJWT := readJWT(t, ts.StoreDir, "O", "accounts", acc, "users", "U.jwt")
	uc, err := jwt.DecodeUserClaims(usrJWT)
	require.NoError(t, err)
	require.NotEqual(t, uc.Issuer, ac.Subject)
	require.Equal(t, uc.IssuerAccount, ac.Subject)
	require.Equal(t, uc.Issuer, ac.SigningKeys.Keys()[0])
}

func Test_EditOperatorRequireSigningKeys(t *testing.T) {
	ts := NewEmptyStore(t)

	_, err := os.Lstat(filepath.Join(ts.Dir, "store"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	// Perform all operations that would end up signing account/user/activation jwt
	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--name", "O")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--sk", "generate")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--require-signing-keys")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "EXPORTER")
	require.NoError(t, err)
	checkAcc(t, ts, "EXPORTER")
	_, _, err = ExecuteCmd(createEditAccount(), "--name", "EXPORTER", "--sk", "generate")
	require.NoError(t, err)
	checkAcc(t, ts, "EXPORTER")
	_, _, err = ExecuteCmd(createAddExportCmd(), "--subject", "sub.public")
	require.NoError(t, err)
	checkAcc(t, ts, "EXPORTER")
	_, _, err = ExecuteCmd(createAddExportCmd(), "--subject", "sub.private", "--private")
	require.NoError(t, err)
	checkAcc(t, ts, "EXPORTER")
	_, _, err = ExecuteCmd(createEditExportCmd(), "--account", "EXPORTER", "--subject", "sub.public", "--description", "foo")
	require.NoError(t, err)
	checkAcc(t, ts, "EXPORTER")
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "A")
	require.NoError(t, err)
	checkAcc(t, ts, "A")
	_, _, err = ExecuteCmd(createEditAccount(), "--name", "A", "--sk", "generate")
	require.NoError(t, err)
	checkAcc(t, ts, "A")
	aAc, err := jwt.DecodeAccountClaims(readJWT(t, ts.StoreDir, "O", "accounts", "A", "A.jwt"))
	require.NoError(t, err)
	expAc, err := jwt.DecodeAccountClaims(readJWT(t, ts.StoreDir, "O", "accounts", "EXPORTER", "EXPORTER.jwt"))
	require.NoError(t, err)
	outpath := filepath.Join(ts.Dir, "token.jwt")
	_, _, err = ExecuteCmd(createGenerateActivationCmd(), "--account", "EXPORTER", "--subject", "sub.private",
		"--target-account", aAc.Subject, "--output-file", outpath)
	require.NoError(t, err)
	act, err := jwt.DecodeActivationClaims(strings.Split(readJWT(t, outpath), "\n")[1]) // strip decoration
	require.NoError(t, err)
	require.NotEqual(t, act.Issuer, act.IssuerAccount)
	require.Equal(t, act.IssuerAccount, expAc.Subject)
	require.Equal(t, act.Issuer, expAc.SigningKeys.Keys()[0])
	_, _, err = ExecuteCmd(createAddImportCmd(), "--account", "A", "--token", outpath)
	require.NoError(t, err)
	checkAcc(t, ts, "A")
	_, _, err = ExecuteCmd(createAddImportCmd(), "--account", "A", "--src-account", expAc.Subject,
		"--remote-subject", "sub.public")
	require.NoError(t, err)
	checkAcc(t, ts, "A")
	_, _, err = ExecuteCmd(createDeleteImportCmd(), "--account", "A", "--subject", "sub.public")
	require.NoError(t, err)
	checkAcc(t, ts, "A")
	_, _, err = ExecuteCmd(createDeleteExportCmd(), "--account", "EXPORTER", "--subject", "sub.public")
	require.NoError(t, err)
	checkAcc(t, ts, "EXPORTER")
	_, _, err = ExecuteCmd(CreateAddUserCmd(), "--account", "A", "--name", "U")
	require.NoError(t, err)
	checkUsr(t, ts, "A")
	_, _, err = ExecuteCmd(createEditUserCmd(), "--account", "A", "--name", "U", "--tag", "foo")
	require.NoError(t, err)
	checkUsr(t, ts, "A")
	_, _, err = ExecuteCmd(createDeleteUserCmd(), "--account", "A", "--name", "U", "--revoke")
	require.NoError(t, err)
	checkAcc(t, ts, "A")
	uk, err := nkeys.CreateUser()
	require.NoError(t, err)
	pubUk, err := uk.PublicKey()
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createRevokeUserCmd(), "--account", "A", "--user-public-key", pubUk)
	require.NoError(t, err)
	checkAcc(t, ts, "A")
}

func Test_EditOperatorRequireSigningKeysManaged(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)
	_, err := os.Lstat(ts.StoreDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	_, pub, kp := CreateOperatorKey(t)
	oc := jwt.NewOperatorClaims(pub)
	oc.Name = "O"
	oc.StrictSigningKeyUsage = true
	_, psk, sk := CreateOperatorKey(t)
	_, err = ts.KeyStore.Store(sk)
	require.NoError(t, err)
	oc.SigningKeys.Add(psk)
	token, err := oc.Encode(kp)
	require.NoError(t, err)
	tf := filepath.Join(ts.Dir, "O.jwt")
	err = Write(tf, []byte(token))
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createAddOperatorCmd(), "--url", tf) // causes a managed store
	require.NoError(t, err)
	// perform operations in a managed store and assure identity is not used
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "A")
	require.NoError(t, err)
	checkAcc(t, ts, "A")
	_, _, err = ExecuteCmd(createEditAccount(), "--name", "A", "--sk", "generate")
	require.NoError(t, err)
	checkAcc(t, ts, "A")
	_, _, err = ExecuteCmd(CreateAddUserCmd(), "--account", "A", "--name", "U")
	require.NoError(t, err)
	checkUsr(t, ts, "A")
	_, _, err = ExecuteCmd(createEditUserCmd(), "--account", "A", "--name", "U", "--tag", "foo")
	require.NoError(t, err)
	checkUsr(t, ts, "A")
}

func Test_EditOperatorSigningKeys(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	s1, pk1, _ := CreateOperatorKey(t)
	_, pk2, _ := CreateOperatorKey(t)

	_, _, err := ExecuteCmd(createEditOperatorCmd(), "--sk", pk1, "--sk", pk2, "--sk", "generate")
	require.NoError(t, err)

	d, err := ts.Store.Read(store.JwtName("O"))
	require.NoError(t, err)

	oc, err := jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)

	require.Contains(t, oc.SigningKeys, pk1)
	require.Contains(t, oc.SigningKeys, pk2)
	require.Len(t, oc.SigningKeys, 3)

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
	ts.AddAccount(t, "SYS")
	pub := ts.GetAccountPublicKey(t, "SYS")

	u1 := "nats://localhost:4222"
	u2 := "tls://localhost:4333"
	as := "nats://localhost:4222"

	// valid from, valid until, add tags, acc jwt server, add service url, url, add another, url, add another,
	// system account (defaults to SYS), add signing key
	inputs := []interface{}{"0", "0", true, "xxx", false, as, true, u1, true, u2, false, true, false, false}

	_, _, err := ExecuteInteractiveCmd(createEditOperatorCmd(), inputs)
	require.NoError(t, err)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Contains(t, oc.OperatorServiceURLs, u1)
	require.Contains(t, oc.OperatorServiceURLs, u2)
	require.Contains(t, oc.Tags, "xxx")
	require.Equal(t, oc.AccountServerURL, as)
	require.Equal(t, oc.SystemAccount, pub)

	// valid from, valid until, acc jwt server, add service url, remove server urls, add signing key
	inputs = []interface{}{"0", "0", true, []int{0}, false, "", false, true, []int{0}, false, false}

	_, _, err = ExecuteInteractiveCmd(createEditOperatorCmd(), inputs)
	require.NoError(t, err)
	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotContains(t, oc.OperatorServiceURLs, u1)
	require.Contains(t, oc.OperatorServiceURLs, u2)
	require.NotContains(t, oc.Tags, "xxx")
	require.Equal(t, oc.AccountServerURL, "")
	require.Equal(t, oc.SystemAccount, pub)
}

func Test_RmAccountServiceURL(t *testing.T) {
	ts := NewTestStore(t, "0")
	defer ts.Done(t)
	as := "https://foo.com/v1/jwt/accounts"
	_, _, err := ExecuteCmd(createEditOperatorCmd(), "--account-jwt-server-url", as)
	require.NoError(t, err)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, as, oc.AccountServerURL)

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--rm-account-jwt-server-url")
	require.NoError(t, err)

	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, "", oc.AccountServerURL)
}

func Test_SKGenerateAddsOneKey(t *testing.T) {
	ts := NewTestStore(t, "0")
	defer ts.Done(t)

	keys, err := ts.KeyStore.AllKeys()
	require.NoError(t, err)
	assert.Equal(t, 1, len(keys))

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--sk", "generate")
	require.NoError(t, err)

	keys, err = ts.KeyStore.AllKeys()
	require.NoError(t, err)
	assert.Equal(t, 2, len(keys))
}

func Test_SysAccountCannotHaveJetStream(t *testing.T) {
	ts := NewTestStore(t, "0")
	defer ts.Done(t)

	// global JS limits shouldn't work
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createEditAccount(), "A", "--js-disk-storage", "1024")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--system-account", "A")
	require.Error(t, err)
	require.Equal(t, err.Error(), "system accounts cannot have JetStream limits - run \"nsc edit account A --js-disable\" first")

	// tiered JS limits shouldn't work
	_, _, err = ExecuteCmd(createEditAccount(), "A", "--js-disable")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createEditAccount(), "A", "--js-tier", "3", "--js-disk-storage", "1024")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--system-account", "A")
	require.Error(t, err)
	require.Equal(t, err.Error(), "system accounts cannot have tiered JetStream limits - run \"nsc edit account A --js-disable\" first")

	_, _, err = ExecuteCmd(createEditAccount(), "A", "--js-disable")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--system-account", "A")
	require.NoError(t, err)
}

func Test_ExpireShouldNotBeUnset(t *testing.T) {
	ts := NewTestStore(t, "0")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createEditOperatorCmd(), "--expiry", "1y")
	require.NoError(t, err)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	now := time.Now().UTC().Year()
	expires := oc.Expires
	year := time.Unix(oc.Expires, 0).UTC().Year()
	require.Equal(t, now+1, year)

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--service-url", "nats://localhost:4222")
	require.NoError(t, err)
	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, expires, oc.Expires)
}

func Test_CannotSetRequireSKWithoutSK(t *testing.T) {
	ts := NewTestStore(t, "0")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createEditOperatorCmd(), "--require-signing-keys")
	require.Error(t, err)
	require.Equal(t, "operator requires at least one signing key", err.Error())

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--require-signing-keys", "--sk", "generate")
	require.NoError(t, err)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--require-signing-keys=false", "--rm-sk", oc.SigningKeys[0])
	require.NoError(t, err)

	oc, err = ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.False(t, oc.StrictSigningKeyUsage)
	require.Empty(t, oc.SigningKeys)
}

func Test_EditOperatorCaseSensitiveTags(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createEditOperatorCmd(), "--case-sensitive-tags", "--tag", "One,Two,three")
	require.Nil(t, err)

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--case-sensitive-tags", "--rm-tag", "Three")
	require.Error(t, err)

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--case-sensitive-tags", "--rm-tag", "three")
	require.NoError(t, err)

	ac, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, ac.Tags, jwt.TagList{"One", "Two"})
}
