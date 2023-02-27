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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
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

func Test_SyncNewer(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	kp := ts.GetAccountKey(t, "A")
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	time.Sleep(time.Second * 2)
	// the client is supposed to update the remote server
	// so this is really just an edge case - we save a newer
	// one than the server has to create the issue
	err = ts.Store.StoreRaw(editAccount(t, kp, m[pk], "test"))
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "test")

	_, _, err = ExecuteCmd(createPullCmd())
	require.Error(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "test")

	// now allow the overwrite
	_, _, err = ExecuteCmd(createPullCmd(), "--overwrite-newer")
	if err != nil {
		panic(err)
	}
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Empty(t, ac.Tags)
}

func Test_SyncNewerFromNatsResolver(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)
	_, _, err := ExecuteCmd(createAddOperatorCmd(), "--name", "OP", "--sys")
	require.NoError(t, err)
	ts.SwitchOperator(t, "OP") // switch the operator so ts is in a usable state to obtain operator key
	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, _, err = ExecuteCmd(createServerConfigCmd(), "--nats-resolver", "--config-file", serverconf)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "AC1")
	require.NoError(t, err)
	// modify the generated file so testing becomes easier by knowing where the jwt directory is
	data, err := os.ReadFile(serverconf)
	require.NoError(t, err)
	dir := ts.AddSubDir(t, "resolver")
	data = bytes.ReplaceAll(data, []byte(`dir: './jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, dir)))
	err = os.WriteFile(serverconf, data, 0660)
	require.NoError(t, err)
	// Create a new account, only known to the nats-server. This account can be pulled
	opKey, err := ts.Store.GetRootPublicKey()
	require.NoError(t, err)
	opKp, err := ts.KeyStore.GetKeyPair(opKey)
	require.NoError(t, err)
	acKp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	subj, err := acKp.PublicKey()
	require.NoError(t, err)
	claimOrig := jwt.NewAccountClaims(subj)
	claimOrig.Name = "acc-name"
	theJwtToPull, err := claimOrig.Encode(opKp)
	require.NoError(t, err)
	os.WriteFile(dir+string(os.PathSeparator)+subj+".jwt", []byte(theJwtToPull), 0660)
	ports := ts.RunServerWithConfig(t, serverconf)
	require.NotNil(t, ports)
	// only after server start as ports are not yet known in tests
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--account-jwt-server-url", ports.Nats[0])
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createPullCmd(), "--all")
	require.NoError(t, err)
	// again, this time with system account and user specified
	_, _, err = ExecuteCmd(createPullCmd(), "--all", "--system-account", "SYS", "--system-user", "sys")
	require.NoError(t, err)
	// claim now exists in nsc store
	claim2, err := ts.Store.ReadAccountClaim("acc-name")
	require.NoError(t, err)
	require.NotEmpty(t, claimOrig.ID)
	require.Equal(t, claimOrig.ID, claim2.ID)
}

func Test_V2OperatorDoesntFail(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp, TasOpts{Vers: 2, OperatorOnlyIfV2: true})
	defer as.Close()

	ts := NewTestStoreWithOperator(t, "T", okp)
	defer ts.Done(t)
	err := ts.Store.StoreRaw(m["operator"])
	require.NoError(t, err)

	// edit the jwt
	_, _, err = ExecuteCmd(createPullCmd(), "-A")
	require.NoError(t, err)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, oc.Version, 2)
}

func Test_V1OperatorDoesntFail(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp, TasOpts{Vers: 2})
	defer as.Close()

	ts := NewTestStoreWithOperator(t, "T", okp)
	defer ts.Done(t)
	err := ts.Store.StoreRaw(m["operator"])
	require.NoError(t, err)

	// edit the jwt
	stdout, stderr, err := ExecuteCmd(createPullCmd(), "-A")
	t.Log(stdout)
	t.Log(stderr)
	require.NoError(t, err)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, oc.Version, 2)
}
