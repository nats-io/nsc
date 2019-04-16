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

func Test_AddCluster(t *testing.T) {
	ts := NewTestStore(t, "add_cluster")
	defer ts.Done(t)

	_, bar, _ := CreateClusterKey(t)
	_, badBar, _ := CreateAccountKey(t)

	tests := CmdTests{
		{createAddClusterCmd(), []string{"add", "cluster"}, nil, []string{"cluster name is required"}, true},
		{createAddClusterCmd(), []string{"add", "cluster", "--name", "foo"}, nil, []string{"Generated cluster key", "added cluster"}, false},
		{createAddClusterCmd(), []string{"add", "cluster", "--name", "foo"}, nil, []string{"the cluster \"foo\" already exists"}, true},
		{createAddClusterCmd(), []string{"add", "cluster", "--name", "foo"}, nil, []string{"the cluster \"foo\" already exists"}, true},
		{createAddClusterCmd(), []string{"add", "cluster", "--name", "bar", "--public-key", bar}, nil, nil, false},
		{createAddClusterCmd(), []string{"add", "cluster", "--name", "badbar", "--public-key", badBar}, nil, []string{"invalid cluster key"}, true},
		{createAddClusterCmd(), []string{"add", "cluster", "--name", "badexp", "--expiry", "2018-01-01"}, nil, []string{"expiry \"2018-01-01\" is in the past"}, true},
		{createAddClusterCmd(), []string{"add", "cluster", "--name", "badexp", "--expiry", "30d"}, nil, nil, false},
	}

	tests.Run(t, "root", "add")
}

func Test_AddClusterNoStore(t *testing.T) {
	// reset the store
	ngsStore = nil
	ForceStoreRoot(t, "")
	_, _, err := ExecuteCmd(createAddClusterCmd())
	require.Equal(t, "no stores available", err.Error())
}

func Test_AddClusterOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddClusterCmd(), "--name", "a", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)
	validateClusterClaims(t, ts)
}

func Test_AddClusterFailsOnManagedStores(t *testing.T) {
	ts := NewTestStoreWithOperator(t, "test", nil)
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddClusterCmd(), "--name", "a")
	require.Error(t, err)
	require.Equal(t, "clusters cannot be created on managed configurations", err.Error())
}

func Test_AddClusterInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	inputs := []interface{}{"a", true, "2018-01-01", "2050-01-01", ts.OperatorKeyPath}

	cmd := createAddClusterCmd()
	HoistRootFlags(cmd)
	_, _, err := ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)
	validateClusterClaims(t, ts)
}

func validateClusterClaims(t *testing.T, ts *TestStore) {
	kp, err := ts.KeyStore.GetClusterKey("a")
	require.NoError(t, err)
	_, err = kp.Seed()
	require.NoError(t, err, "stored key should be a seed")

	ac, err := ts.Store.ReadClusterClaim("a")
	require.NoError(t, err, "reading cluster claim")

	pub, err := kp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, ac.Subject, pub, "public key is subject")

	okp, err := ts.KeyStore.GetOperatorKey("test")
	require.NoError(t, err)

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
