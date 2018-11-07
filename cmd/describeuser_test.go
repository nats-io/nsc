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
	"strings"
	"testing"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestDescribeUser(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	os.Setenv(store.DataProfileEnv, "test")
	InitStore(t)

	p := AddUserParams{}
	_, p.publicKey, _ = CreateUser(t)
	p.name = "Test User"
	p.tags = append(p.tags, "user")

	AddUserFromParams(t, &p)

	tests := CmdTests{
		{createDescribeUserCmd(), []string{"describe", "user"}, nil, []string{"error specify one of --public-key or --interactive to select an user"}, true},
		{createDescribeUserCmd(), []string{"describe", "user", "-m"}, nil, []string{"flag needs an argument"}, true},
		{createDescribeUserCmd(), []string{"describe", "user", "-m", "user"}, nil, nil, false},
		{createDescribeUserCmd(), []string{"describe", "user", "-k", p.publicKey}, nil, nil, false},
		{createDescribeUserCmd(), []string{"describe", "user", "-k", "foo"}, nil, []string{"error decoding public key"}, true},
		{createDescribeUserCmd(), []string{"describe", "user", "-m", "account"}, nil, []string{"didn't match anything"}, true},
		{createDescribeUserCmd(), []string{"describe", "user", "-k", "UCKSHQKMOFDAQLY7QBRLUWIBXO3PGROCJ2CN2UA5GNBAFXCEW7YQCGKP"}, nil, []string{"was not found"}, true},
	}

	tests.Run(t, "root", "describe")
}

func ParseUserReport(t *testing.T, s string) AddUserParams {
	v := AddUserParams{}

	s = StripTableDecorations(s)

	lines := strings.Split(s, "\n")

	for _, l := range lines {
		kv := strings.Split(l, ":")
		kv[0] = strings.TrimSpace(kv[0])
		switch kv[0] {
		case "User":
			v.name = strings.TrimSpace(kv[1])
		case "Publish Permissions":
			kv[1] = strings.TrimSpace(kv[1])
			v.allowPubs = strings.Split(kv[1], ",")
		case "Deny Publish Permissions":
			kv[1] = strings.TrimSpace(kv[1])
			v.denyPubs = strings.Split(kv[1], ",")
		case "Subscribe Permissions":
			kv[1] = strings.TrimSpace(kv[1])
			v.allowSubs = strings.Split(kv[1], ",")
		case "Deny Subscribe Permissions":
			kv[1] = strings.TrimSpace(kv[1])
			v.denySubs = strings.Split(kv[1], ",")
		case "Tags":
			kv[1] = strings.TrimSpace(kv[1])
			v.tags = strings.Split(kv[1], ",")
		case "Max Messages":
			v.max = strings.TrimSpace(kv[1])
		case "Max Payload":
			v.payload = strings.TrimSpace(kv[1])
		case "Public Key":
			v.publicKey = strings.TrimSpace(kv[1])
		}
	}
	return v
}

func TestDescribeUserCmdWithTag(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	os.Setenv(store.DataProfileEnv, "test")
	InitStore(t)

	p := AddUserParams{}
	_, p.publicKey, _ = CreateUser(t)
	p.name = "Test User"
	p.allowPubs = append(p.allowPubs, "foo")
	p.allowSubs = append(p.allowSubs, "bar")
	p.denyPubs = append(p.denyPubs, "baz")
	p.denySubs = append(p.denySubs, "foobar")
	p.tags = append(p.tags, "user")
	p.max = "1000"
	p.payload = "128"

	AddUserFromParams(t, &p)

	stdout, _, err := ExecuteCmd(createDescribeUserCmd(), "-m", "user")
	require.NoError(t, err)

	p2 := ParseUserReport(t, stdout)
	require.Equal(t, p, p2)
}

func TestDescribeUserCmdWithKey(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	os.Setenv(store.DataProfileEnv, "test")
	InitStore(t)

	p := AddUserParams{}
	_, p.publicKey, _ = CreateUser(t)
	p.name = "Test User"
	p.allowPubs = append(p.allowPubs, "foo")
	p.allowSubs = append(p.allowSubs, "bar")
	p.tags = append(p.tags, "user")
	p.max = "1000"
	p.payload = "128"

	AddUserFromParams(t, &p)

	stdout, _, err := ExecuteCmd(createDescribeUserCmd(), "-k", p.publicKey)
	require.NoError(t, err)

	p2 := ParseUserReport(t, stdout)
	require.Equal(t, p, p2)
}
