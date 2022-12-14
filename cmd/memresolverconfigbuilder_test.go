/*
 * Copyright 2018-2019 The NATS Authors
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

	"github.com/nats-io/nats-server/v2/server"
	"github.com/stretchr/testify/require"

	"github.com/nats-io/nsc/v2/cmd/store"
)

func Test_MemResolverContainsStandardProperties(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	builder := NewMemResolverConfigBuilder()

	o, err := ts.Store.Read(store.JwtName("O"))
	require.NoError(t, err)
	err = builder.Add(o)
	require.NoError(t, err)

	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	d, err := builder.Generate()
	require.NoError(t, err)

	conf := string(d)
	require.Contains(t, conf, "resolver: MEMORY")
	require.Contains(t, conf, "resolver_preload: {")
}

func Test_MemResolverNotContainsOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	builder := NewMemResolverConfigBuilder()
	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	_, err = builder.Generate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "operator is not set")
}

func Test_MemResolverContainsOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	builder := NewMemResolverConfigBuilder()

	o, err := ts.Store.Read(store.JwtName("O"))
	require.NoError(t, err)
	err = builder.Add(o)
	require.NoError(t, err)

	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	d, err := builder.Generate()
	require.NoError(t, err)

	conf := string(d)
	require.Contains(t, conf, string(o))
}

func Test_MemResolverFiltersNonAccounts(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "A", "ua")

	builder := NewMemResolverConfigBuilder()

	o, err := ts.Store.Read(store.JwtName("O"))
	require.NoError(t, err)
	err = builder.Add(o)
	require.NoError(t, err)

	aac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	apk := aac.Subject
	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	ua, err := ts.Store.Read(store.Accounts, "A", store.Users, store.JwtName("ua"))
	require.NoError(t, err)
	err = builder.Add(ua)
	require.NoError(t, err)

	bac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	bpk := bac.Subject
	b, err := ts.Store.Read(store.Accounts, "B", store.JwtName("B"))
	require.NoError(t, err)
	err = builder.Add(b)
	require.NoError(t, err)

	d, err := builder.Generate()
	require.NoError(t, err)

	conf := string(d)

	require.NotContains(t, conf, o)
	require.NotContains(t, conf, ua)
	require.Contains(t, conf, fmt.Sprintf(" %s: %s\n", apk, string(a)))
	require.Contains(t, conf, fmt.Sprintf(" %s: %s\n", bpk, string(b)))
}

func Test_MemResolverErrorBadClaim(t *testing.T) {
	builder := NewMemResolverConfigBuilder()
	require.Error(t, builder.Add([]byte("bad")))
}

func Test_MemResolverDir(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	out := filepath.Join(ts.Dir, "conf")
	_, _, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--dir", out)
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(out, "O.jwt"))
	require.FileExists(t, filepath.Join(out, "A.jwt"))
	require.FileExists(t, filepath.Join(out, "B.jwt"))
	resolver := filepath.Join(out, "resolver.conf")
	require.FileExists(t, resolver)
	d, err := os.ReadFile(resolver)
	require.NoError(t, err)

	contents := string(d)
	require.Contains(t, contents, fmt.Sprintf("operator: %q", "O.jwt"))
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, contents, fmt.Sprintf("%s: %q", ac.Subject, "A.jwt"))

	bc, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Contains(t, contents, fmt.Sprintf("%s: %q", bc.Subject, "B.jwt"))
}

func Test_MemResolverServerParse(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	serverconf := filepath.Join(ts.Dir, "server.conf")

	_, _, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--config-file", serverconf)

	require.NoError(t, err)

	var opts server.Options
	require.NoError(t, opts.ProcessConfigFile(serverconf))
}

func Test_MemResolverContainsSysAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	stdout, _, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--sys-account", "B")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Contains(t, stdout, fmt.Sprintf("system_account: %s", ac.Subject))
}
