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
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_SyncOK(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp, TasOpts{Vers: 2})
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
	require.True(t, ac.Tags.Contains("A"))
}

func Test_SyncNoURL(t *testing.T) {
	_, _, okp := CreateOperatorKey(t)
	as, m := RunTestAccountServerWithOperatorKP(t, okp, TasOpts{Vers: 2})
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
	as, m := RunTestAccountServerWithOperatorKP(t, okp, TasOpts{Vers: 2})
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
	_, _, err = ExecuteCmd(createEditAccount(), "--tag", "a")
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

	ts := NewTestStore(t, "O")
	ts.AddAccount(t, "SYS")
	ts.AddAccount(t, "AC1")
	ts.AddAccount(t, "AC2")

	_, _, err := ExecuteCmd(createEditOperatorCmd(), "--system-account", "SYS")
	require.NoError(t, err)

	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, _, err = ExecuteCmd(createServerConfigCmd(), "--nats-resolver", "--config-file", serverconf)
	require.NoError(t, err)

	// modify the generated file so testing becomes easier by knowing where the jwt directory is
	data, err := os.ReadFile(serverconf)
	require.NoError(t, err)
	dir := ts.AddSubDir(t, "resolver")
	data = bytes.ReplaceAll(data, []byte(`dir: './jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, dir)))
	data = bytes.ReplaceAll(data, []byte(`dir: '.\jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, dir)))
	data = bytes.ReplaceAll(data, []byte(`allow_delete: false`), []byte(fmt.Sprintf(`allow_delete: %t`, del)))
	err = os.WriteFile(serverconf, data, 0660)
	require.NoError(t, err)
	ports := ts.RunServerWithConfig(t, serverconf)
	require.NotNil(t, ports)
	// only after server start as ports are not yet known in tests
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--account-jwt-server-url", ports.Nats[0])
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createPushCmd(), "--all")
	require.NoError(t, err)
	// test to assure AC1/AC2/SYS where pushed
	filesPre, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt")
	require.NoError(t, err)
	require.Equal(t, len(filesPre), 3)
	_, _, err = ExecuteCmd(createDeleteAccountCmd(), "--name", "AC2")
	require.NoError(t, err)
	// exists as nsc has a bad default account now (is not pushed, hence not in file counts)
	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "AC3")
	require.NoError(t, err)
	return dir, filesPre, ts
}

func Test_SyncNatsResolverDeleteNoOperatorKey(t *testing.T) {
	_, _, ts := deleteSetup(t, true)
	defer ts.Done(t)

	opk, err := ts.OperatorKey.PublicKey()
	require.NoError(t, err)
	require.NoError(t, ts.KeyStore.Remove(opk))

	_, stderr, err := ExecuteCmd(createPushCmd(), "--prune")
	t.Log(stderr)
	require.Error(t, err)
}

func Test_SyncNatsResolverDeleteOperatorKeyInFlag(t *testing.T) {
	_, _, ts := deleteSetup(t, true)
	defer ts.Done(t)

	okp := ts.OperatorKey
	seed, err := okp.Seed()
	require.NoError(t, err)

	opk, err := ts.OperatorKey.PublicKey()
	require.NoError(t, err)
	require.NoError(t, ts.KeyStore.Remove(opk))

	cmd := createPushCmd()
	HoistRootFlags(cmd)
	_, _, err = ExecuteCmd(cmd, "--prune", "-K", string(seed))
	require.NoError(t, err)
}

func Test_SyncNatsResolverDelete(t *testing.T) {
	dir, filesPre, ts := deleteSetup(t, true)
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createPushCmd(), "--prune")
	require.NoError(t, err)
	// test to assure AC1/SYS where pushed/pruned
	filesPost, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt")
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
	filesDeleted, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt.deleted")
	require.NoError(t, err)
	require.Equal(t, 1, len(filesDeleted))
}

func Test_SyncNatsResolverExplicitDelete(t *testing.T) {
	dir, filesPre, ts := deleteSetup(t, true)
	defer os.Remove(dir)
	defer ts.Done(t)
	_, _, err := ExecuteCmd(createPushCmd(), "--account-removal", "AC1")
	require.NoError(t, err)
	// test to assure AC1/SYS where pushed/pruned
	filesPost, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt")
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
	filesDeleted, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt.deleted")
	require.NoError(t, err)
	require.Equal(t, 1, len(filesDeleted))
}

func Test_SyncNatsResolverDiff(t *testing.T) {
	dir, _, ts := deleteSetup(t, true)
	defer os.Remove(dir)
	defer ts.Done(t)
	_, stdErr, err := ExecuteCmd(createPushCmd(), "--diff")
	require.NoError(t, err)
	require.Contains(t, stdErr, "only exists in server")
	require.Contains(t, stdErr, "named AC1 exists")
	require.Contains(t, stdErr, "named SYS exists")

	re := regexp.MustCompile("[A-Z0-9]* named AC1 exists")
	line := re.FindString(stdErr)
	accId := strings.TrimSuffix(line, " named AC1 exists")

	_, _, err = ExecuteCmd(createPushCmd(), "--account-removal", accId)
	require.NoError(t, err)
	filesDeleted, err := filepath.Glob(dir + string(os.PathSeparator) + accId + ".jwt.deleted")
	require.NoError(t, err)
	require.Equal(t, 1, len(filesDeleted))
	_, stdErr, err = ExecuteCmd(createPushCmd(), "--diff")
	require.NoError(t, err)
	require.Contains(t, stdErr, "only exists in server")
	require.NotContains(t, stdErr, "named AC1 exists")
	require.Contains(t, stdErr, "named SYS exists")
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
	filesPost, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt")
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
	filesPost, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt")
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
	data, err := os.ReadFile(serverconf)
	require.NoError(t, err)
	dir := ts.AddSubDir(t, "resolver")
	data = bytes.ReplaceAll(data, []byte(`dir: './jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, dir)))
	err = os.WriteFile(serverconf, data, 0660)
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
	// Provide explicit system account user to connect
	_, _, err = ExecuteCmd(createPushCmd(), "--all", "--system-account", "SYS", "--system-user", "sys")
	require.NoError(t, err)
	// test to assure AC1/AC2/SYS where pushed
	filesPre, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt")
	require.NoError(t, err)
	require.Equal(t, len(filesPre), 2)
}

func Test_SyncWs(t *testing.T) {
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
	data, err := os.ReadFile(serverconf)
	require.NoError(t, err)
	dir := ts.AddSubDir(t, "resolver")

	ws := `websocket: { 
  port: -1 
  no_tls: true
}`
	data = append(data, ws...)
	data = bytes.ReplaceAll(data, []byte(`dir: './jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, dir)))
	err = os.WriteFile(serverconf, data, 0660)
	require.NoError(t, err)
	ports := ts.RunServerWithConfig(t, serverconf)
	require.NotNil(t, ports)
	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--account-jwt-server-url", ports.WebSocket[0])
	require.NoError(t, err)
	// Try again, thus also testing if the server is still around
	// Provide explicit system account user to connect
	_, _, err = ExecuteCmd(createPushCmd(), "--all", "--system-account", "SYS", "--system-user", "sys")
	require.NoError(t, err)
	// test to assure AC1/AC2/SYS where pushed
	filesPre, err := filepath.Glob(dir + string(os.PathSeparator) + "*.jwt")
	require.NoError(t, err)
	require.Equal(t, len(filesPre), 2)
}
