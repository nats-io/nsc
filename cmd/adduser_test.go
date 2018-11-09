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

func TestAddUser(t *testing.T) {
	seed, pub, _ := CreateUser(t)
	_, pub2, _ := CreateUser(t)
	aseed, apub, _ := CreateAccount(t)

	_, _, _ = CreateTestStore(t)

	tests := CmdTests{
		{createAddUserCmd(), []string{"add", "user"}, nil, []string{"--public-key", "--generate-nkeys"}, true},
		{createAddUserCmd(), []string{"add", "user", "--public-key", pub, "--generate-nkeys"}, nil, []string{"error specify one of"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--max-messages", "abc"}, nil, nil, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--max-messages", "10"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--max-messages", "10K"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--max-messages", "10M"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--max-payload", "abc"}, nil, nil, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--max-payload", "10"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--max-payload", "10K"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--max-payload", "10M"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--allow-pub"}, nil, []string{"flag needs an argument"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--allow-pub", "a,b,c"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--allow-sub"}, nil, []string{"flag needs an argument"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--allow-sub", "a,b,c"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--allow-pubsub"}, nil, []string{"flag needs an argument"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--allow-pubsub", "a,b,c"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--deny-pub"}, nil, []string{"flag needs an argument"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--deny-pub", "a,b,c"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--deny-sub"}, nil, []string{"flag needs an argument"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--deny-sub", "a,b,c"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--deny-pubsub"}, nil, []string{"flag needs an argument"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--deny-pubsub", "a,b,c"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--source-network", "192.168.1.0/32"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--public-key", string(seed)}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--public-key", pub}, nil, []string{"already exists"}, true},
		{createAddUserCmd(), []string{"add", "user", "--public-key", pub2}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--public-key", string(aseed)}, nil, []string{"doesn't look like user nkey"}, true},
		{createAddUserCmd(), []string{"add", "user", "--public-key", apub}, nil, []string{"doesn't look like user nkey"}, true},
		{createAddUserCmd(), []string{"add", "user", "--tag"}, nil, []string{"flag needs an argument"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--tag", "a,b,c"}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--name"}, nil, []string{"flag needs an argument"}, true},
		{createAddUserCmd(), []string{"add", "user", "--generate-nkeys", "--name", "alberto"}, nil, nil, false},
	}
	tests.Run(t, "root", "add")

}

func TestAddUserData(t *testing.T) {
	_, _, _ = CreateTestStore(t)

	up := CreateUserParams(t, "test")
	_, _, err := ExecuteCmd(createAddUserCmd(), up.AsArgs()...)
	require.NoError(t, err)

	u := User{}
	u.PublicKey = up.publicKey
	err = u.Load()
	require.NoError(t, err)

	_10K, _ := ParseNumber("10K")
	_1M, _ := ParseDataSize("1M")
	require.Equal(t, up.publicKey, u.PublicKey, "publicKey")
	require.Equal(t, _10K, u.Max, "max")
	require.Equal(t, _1M, u.Payload, "payload")
	require.ElementsMatch(t, []string{"a", "b", "e", "f"}, u.Pub.Allow, "allow pub")
	require.ElementsMatch(t, []string{"c", "d", "e", "f"}, u.Sub.Allow, "allow sub")
	require.ElementsMatch(t, []string{"u", "v", "y", "z"}, u.Pub.Deny, "deny pub")
	require.ElementsMatch(t, []string{"w", "x", "y", "z"}, u.Sub.Deny, "deny sub")
	require.ElementsMatch(t, []string{"t1", "t2"}, u.Tag, "tag")
}
