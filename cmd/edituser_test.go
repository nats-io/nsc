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
	"os"
	"testing"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestEditUser(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	os.Setenv(store.DataProfileEnv, "test")
	InitStore(t)

	p := AddUserParams{}
	_, p.publicKey, _ = CreateUser(t)
	p.name = "A"
	p.tags = append(p.tags, "user")

	AddUserFromParams(t, &p)

	tests := CmdTests{
		{createEditUserCmd(), []string{"edit", "user"}, nil, []string{"error specify one of --public-key or --interactive to select an user"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "-m"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--allow-pub"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--allow-sub"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--allow-pubsub"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--add-tag"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--add-source-network"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--max-messages"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--max-payload"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--name"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--rm"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--rm-source-network"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--public-key", p.publicKey, "--rm-tag"}, nil, []string{"flag needs an argument"}, true},
		{createEditUserCmd(), []string{"edit", "user", "-m", "user", "-i"}, nil, []string{"one of --interactive or --match to select an user"}, true},
	}

	tests.Run(t, "root", "edit")
}

func TestUserEdits(t *testing.T) {
	type validator func(u *User)

	tests := []struct {
		createFlags []string
		editFlags   []string
		vF          validator
	}{
		{[]string{"--name", "A"}, []string{"--name", "B"}, func(u *User) {
			require.Equal(t, "B", u.Name, "set name")
		}},
		{[]string{"--max-payload", "1"}, []string{"--max-payload", "12"}, func(u *User) {
			require.Equal(t, int64(12), u.Payload, "payload")
		}},
		{[]string{"--max-messages", "2"}, []string{"--max-messages", "21"}, func(u *User) {
			require.Equal(t, int64(21), u.Max, "max")
		}},
		{[]string{"--tag", "d"}, []string{"--add-tag", "a,b,c"}, func(u *User) {
			require.ElementsMatch(t, []string{"a", "b", "c", "d"}, u.Tag, "add tag")
		}},
		{[]string{"--allow-pub", "foo"}, []string{"--allow-pub", "bar,>"}, func(u *User) {
			require.ElementsMatch(t, []string{"foo", "bar", ">"}, u.Pub.Allow, "allow pub")
		}},
		{[]string{"--allow-sub", "baz"}, []string{"--allow-sub", "*"}, func(u *User) {
			require.ElementsMatch(t, []string{"baz", "*"}, u.Sub.Allow, "allow sub")
		}},
		{[]string{"--source-network", "192.0.0.0/12"}, []string{"--add-source-network", "192.168.0.0/24"}, func(u *User) {
			require.Equal(t, "192.0.0.0/12,192.168.0.0/24", u.Src, "add src")
		}},
		{[]string{"--allow-pubsub", "z"}, []string{"--allow-pubsub", "y"}, func(u *User) {
			require.ElementsMatch(t, []string{"z", "y"}, u.Pub.Allow, "pubsub pubs")
			require.ElementsMatch(t, []string{"z", "y"}, u.Sub.Allow, "pubsub sub")
		}},
		{[]string{"--tag", "A,B"}, []string{"--rm-tag", "A"}, func(u *User) {
			require.ElementsMatch(t, []string{"B"}, u.Tag, "rm tag")
		}},
		{[]string{"--allow-pub", "foo,bar"}, []string{"--rm", "foo"}, func(u *User) {
			require.ElementsMatch(t, []string{"bar"}, u.Pub.Allow, "rm pub")
		}},
		{[]string{"--allow-sub", "baz,foobar"}, []string{"--rm", "baz"}, func(u *User) {
			require.ElementsMatch(t, []string{"foobar"}, u.Sub.Allow, "rm sub")
		}},
		{[]string{"--allow-pubsub", "baz,foobar"}, []string{"--rm", "baz"}, func(u *User) {
			require.ElementsMatch(t, []string{"foobar"}, u.Pub.Allow, "rm pub")
			require.ElementsMatch(t, []string{"foobar"}, u.Sub.Allow, "rm sub")
		}},
		{[]string{"--source-network", "192.168.0.0/16,192.0.0.0/16"}, []string{"--rm-source-network", "192.168.0.0/16"}, func(u *User) {
			require.Equal(t, "192.0.0.0/16", u.Src, "rm src")
		}},
		{[]string{"--deny-pub", "foo,bar"}, []string{"--rm", "bar"}, func(u *User) {
			require.ElementsMatch(t, []string{"foo"}, u.Pub.Deny, "rm deny pub")
		}},
		{[]string{"--deny-sub", "foo,bar"}, []string{"--rm", "bar"}, func(u *User) {
			require.ElementsMatch(t, []string{"foo"}, u.Sub.Deny, "rm deny sub")
		}},
		{[]string{"--deny-pubsub", "foo,bar"}, []string{"--rm", "bar"}, func(u *User) {
			require.ElementsMatch(t, []string{"foo"}, u.Sub.Deny, "rm deny sub")
			require.ElementsMatch(t, []string{"foo"}, u.Pub.Deny, "rm deny pub")
		}},
	}

	for _, v := range tests {
		dir := MakeTempDir(t)
		os.Setenv(store.DataHomeEnv, dir)
		os.Setenv(store.DataProfileEnv, "test")
		InitStore(t)

		_, pk, _ := CreateUser(t)
		AddUser(t, pk, v.createFlags...)

		u := EditUser(t, pk, v.editFlags...)
		v.vF(u)
	}
}
