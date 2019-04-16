/*
 * Copyright 2018 The NATS Authors
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

func Test_AddServer(t *testing.T) {
	ts := NewTestStore(t, "add_server")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddClusterCmd(), "--name", "c")
	require.NoError(t, err, "cluster creation")

	_, bar, _ := CreateServerKey(t)
	_, badBar, _ := CreateAccountKey(t)

	tests := CmdTests{
		{createAddServerCmd(), []string{"add", "server"}, nil, []string{"server name is required"}, true},
		{createAddServerCmd(), []string{"add", "server", "--name", "foo"}, nil, []string{"Generated server key", "added server"}, false},
		{createAddServerCmd(), []string{"add", "server", "--name", "foo"}, nil, []string{"the server \"foo\" already exists"}, true},
		{createAddServerCmd(), []string{"add", "server", "--name", "foo"}, nil, []string{"the server \"foo\" already exists"}, true},
		{createAddServerCmd(), []string{"add", "server", "--name", "bar", "--public-key", bar}, nil, nil, false},
		{createAddServerCmd(), []string{"add", "server", "--name", "badbar", "--public-key", badBar}, nil, []string{"invalid server key"}, true},
		{createAddServerCmd(), []string{"add", "server", "--name", "badexp", "--expiry", "2018-01-01"}, nil, []string{"expiry \"2018-01-01\" is in the past"}, true},
		{createAddServerCmd(), []string{"add", "server", "--name", "badexp", "--expiry", "30d"}, nil, nil, false},
	}

	tests.Run(t, "root", "add")
}

func Test_AddServerNoStore(t *testing.T) {
	// reset the store
	ngsStore = nil
	ForceStoreRoot(t, "")
	_, _, err := ExecuteCmd(createAddServerCmd())
	require.Equal(t, "no stores available", err.Error())
}

func Test_AddServerOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddClusterCmd(), "--name", "c")
	require.NoError(t, err, "cluster creation")

	_, _, err = ExecuteCmd(createAddServerCmd(), "--name", "a", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)
	validateServerClaim(t, ts)
}

func Test_AddServerInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddClusterCmd(), "--name", "c")
	require.NoError(t, err, "cluster creation")

	inputs := []interface{}{"a", true, "2018-01-01", "2050-01-01", ts.KeyStore.GetClusterKeyPath("c")}

	cmd := createAddServerCmd()
	HoistRootFlags(cmd)
	_, _, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)
	validateServerClaim(t, ts)
}

func validateServerClaim(t *testing.T, ts *TestStore) {
	skp, err := ts.KeyStore.GetServerKey("c", "a")
	require.NoError(t, err)
	_, err = skp.Seed()
	require.NoError(t, err, "stored key should be a seed")

	sc, err := ts.Store.ReadServerClaim("c", "a")
	require.NoError(t, err, "reading server claim")

	pub, err := skp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, sc.Subject, pub, "public key is subject")

	okp, err := ts.KeyStore.GetClusterKey("c")
	require.NoError(t, err)

	oppub, err := okp.PublicKey()
	require.NoError(t, err, "getting public key for operator")
	require.Equal(t, sc.Issuer, oppub, "operator signed it")

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)
	require.Equal(t, start, sc.NotBefore)

	expire, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)
	require.Equal(t, expire, sc.Expires)
}
