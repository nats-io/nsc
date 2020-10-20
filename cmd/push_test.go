/*
 * Copyright 2018-2020 The NATS Authors
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
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/stretchr/testify/require"
)

func Test_SyncOK(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp)
	defer as.Close()

	ts := NewTestStoreWithOperator(t, "T", okp)
	err := ts.Store.StoreRaw(m["operator"])
	require.NoError(t, err)
	ts.AddAccount(t, "A")

	// edit the jwt
	_, _, err = ExecuteCmd(createEditAccount(), "--tag", "A")
	require.NoError(t, err)

	// sync the store
	_, _, err = ExecuteCmd(createPushCmd(), "--account", "A")
	require.NoError(t, err)

	// verify the tag was stored
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "a")
}

func Test_SyncNoURL(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp)
	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	ts.AddAccount(t, "A")
	as.Close()

	// remove the account server so we cannot push
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	oc.AccountServerURL = ""
	token, err := oc.Encode(okp)
	require.NoError(t, err)
	ts.Store.StoreClaim([]byte(token))

	_, _, err = ExecuteCmd(createPushCmd(), "--account", "A")
	require.Error(t, err)
	t.Log(err.Error())
	require.Contains(t, err.Error(), "no account server url or nats-server url was provided by the operator jwt")
}

func Test_SyncNoServer(t *testing.T) {
	as, m := RunTestAccountServer(t)
	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	ts.AddAccount(t, "A")
	as.Close()

	_, stderr, err := ExecuteCmd(createPushCmd(), "--account", "A")
	require.Error(t, err)
	if runtime.GOOS == "windows" {
		require.Contains(t, stderr, "connectex: No connection")
	} else {
		require.Contains(t, stderr, "connect: connection refused")
	}
}

func Test_SyncManaged(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.False(t, ac.IsSelfSigned())
}

func Test_SyncManualServer(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp)
	defer as.Close()

	// remove the account server
	op, err := jwt.DecodeOperatorClaims(string(m["operator"]))
	require.NoError(t, err)
	op.AccountServerURL = ""
	s, err := op.Encode(okp)
	require.NoError(t, err)
	m["operator"] = []byte(s)

	ts := NewTestStoreWithOperator(t, "T", okp)
	err = ts.Store.StoreRaw(m["operator"])
	require.NoError(t, err)
	ts.AddAccount(t, "A")

	// edit the jwt
	_, _, err = ExecuteCmd(createEditAccount(), "--tag", "A")
	require.NoError(t, err)

	// sync the store
	_, _, err = ExecuteCmd(createPushCmd(), "--account", "A", "--account-jwt-server-url", as.URL)
	require.NoError(t, err)

	// verify the tag was stored
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Tags, "a")
}

func deleteSetup(t *testing.T, del bool) (string, []string, *TestStore) {
	t.Helper()
	ts := NewEmptyStore(t)
	_, _, err := ExecuteCmd(createAddOperatorCmd(), "--name", "OP", "--sys")
	require.NoError(t, err)
	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, _, err = ExecuteCmd(createServerConfigCmd(), "--nats-resolver", "--config-file", serverconf)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "AC1")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "AC2")
	require.NoError(t, err)
	// modify the generated file so testing becomes easier by knowing where the jwt directory is
	data, err := ioutil.ReadFile(serverconf)
	require.NoError(t, err)
	dir, err := ioutil.TempDir("", "Test_SyncNatsResolver-jwt-")
	require.NoError(t, err)
	data = bytes.ReplaceAll(data, []byte(`dir: './jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, dir)))
	data = bytes.ReplaceAll(data, []byte(`allow_delete: false`), []byte(fmt.Sprintf(`allow_delete: %t`, del)))
	err = ioutil.WriteFile(serverconf, data, 0660)
	require.NoError(t, err)
	ports := ts.RunServerWithConfig(t, serverconf)
	require.NotNil(t, ports)
	// only after server start as ports are not yet known in tests
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--account-jwt-server-url", ports.Nats[0])
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createPushCmd(), "--all")
	require.NoError(t, err)
	// test to assure AC1/AC2/SYS where pushed
	filesPre, err := filepath.Glob(dir + string(os.PathSeparator) + "/*.jwt")
	require.NoError(t, err)
	require.Equal(t, len(filesPre), 3)
	_, _, err = ExecuteCmd(createDeleteAccountCmd(), "--name", "AC2")
	require.NoError(t, err)
	// exists as nsc has a bad default account now (is not pushed, hence not in file counts)
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "AC3")
	require.NoError(t, err)
	return dir, filesPre, ts
}

func Test_SyncNatsResolverDelete(t *testing.T) {
	dir, filesPre, ts := deleteSetup(t, true)
	defer os.Remove(dir)
	defer ts.Done(t)
	_, _, err := ExecuteCmd(createPushCmd(), "--prune")
	require.NoError(t, err)
	// test to assure AC1/SYS where pushed/pruned
	filesPost, err := filepath.Glob(dir + string(os.PathSeparator) + "/*.jwt")
	require.NoError(t, err)
	require.Equal(t, 2, len(filesPost))
	// assert only AC1/SYS overlap in pre/post
	sameCnt := 0
	for _, f1 := range filesPost {
		for _, f2 := range filesPre {
			if f1 == f2 {
				sameCnt++
				break
			}
		}
	}
	require.Equal(t, 2, sameCnt)
	filesDeleted, err := filepath.Glob(dir + string(os.PathSeparator) + "/*.jwt.deleted")
	require.NoError(t, err)
	require.Equal(t, 1, len(filesDeleted))
}

func Test_SyncNatsResolverDeleteSYS(t *testing.T) {
	dir, filesPre, ts := deleteSetup(t, true)
	defer os.Remove(dir)
	defer ts.Done(t)
	_, _, err := ExecuteCmd(createDeleteAccountCmd(), "--name", "SYS")
	require.NoError(t, err)
	// exists as nsc has a bad default account now (is not pushed, hence not in file counts)
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "AC4")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createPushCmd(), "--prune") // will fail as system acc can't be deleted
	require.Error(t, err)                              // this will actually not hit the server as the system account is already deleted
	filesPost, err := filepath.Glob(dir + string(os.PathSeparator) + "/*.jwt")
	require.NoError(t, err)
	require.Equal(t, 3, len(filesPost))
	require.Equal(t, filesPre, filesPost)
}

func Test_SyncNatsResolverNoDelete(t *testing.T) {
	dir, filesPre, ts := deleteSetup(t, false)
	defer os.Remove(dir)
	defer ts.Done(t)
	_, _, err := ExecuteCmd(createPushCmd(), "--prune")
	require.Error(t, err)
	// test to assure that pruning did not happen
	filesPost, err := filepath.Glob(dir + string(os.PathSeparator) + "/*.jwt")
	require.NoError(t, err)
	require.Equal(t, 3, len(filesPost))
	require.Equal(t, filesPre, filesPost)
}

func Test_SyncBadUrl(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)
	_, _, err := ExecuteCmd(createAddOperatorCmd(), "--name", "OP", "--sys")
	require.NoError(t, err)
	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, _, err = ExecuteCmd(createServerConfigCmd(), "--nats-resolver", "--config-file", serverconf)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "AC1")
	require.NoError(t, err)
	// modify the generated file so testing becomes easier by knowing where the jwt directory is
	data, err := ioutil.ReadFile(serverconf)
	require.NoError(t, err)
	dir, err := ioutil.TempDir("", "Test_SyncNatsResolver-jwt-")
	require.NoError(t, err)
	defer os.Remove(dir)
	data = bytes.ReplaceAll(data, []byte(`dir: './jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, dir)))
	err = ioutil.WriteFile(serverconf, data, 0660)
	require.NoError(t, err)
	ports := ts.RunServerWithConfig(t, serverconf)
	require.NotNil(t, ports)
	// deliberately test if http push to a nats server kills it or not
	badUrl := strings.ReplaceAll(ports.Nats[0], "nats://", "http://")
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--account-jwt-server-url", badUrl)
	require.NoError(t, err)
	_, errOut, err := ExecuteCmd(createPushCmd(), "--all")
	require.Error(t, err)
	require.Contains(t, errOut, `Post "`+badUrl)
	// Fix bad url
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--account-jwt-server-url", ports.Nats[0])
	require.NoError(t, err)
	// Try again, thus also testing if the server is still around
	_, _, err = ExecuteCmd(createPushCmd(), "--all")
	require.NoError(t, err)
	// test to assure AC1/AC2/SYS where pushed
	filesPre, err := filepath.Glob(dir + string(os.PathSeparator) + "/*.jwt")
	require.NoError(t, err)
	require.Equal(t, len(filesPre), 2)
}
