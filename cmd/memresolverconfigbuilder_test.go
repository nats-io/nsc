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
	"path/filepath"
	"testing"

	"github.com/nats-io/gnatsd/server"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_MemResolverContainsStandardProperties(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	builder := NewMemResolverConfigBuilder()
	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	d, err := builder.Generate("")
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

	d, err := builder.Generate("")
	require.NoError(t, err)

	conf := string(d)
	require.NotContains(t, conf, "operator:")
}

func Test_MemResolverContainsOperator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	builder := NewMemResolverConfigBuilder()
	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	d, err := builder.Generate("/bogus/operator.jwt")
	require.NoError(t, err)

	conf := string(d)
	require.Contains(t, conf, "operator: \"/bogus/operator.jwt\"")
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
	bpk := bac.Subject
	b, err := ts.Store.Read(store.Accounts, "B", store.JwtName("B"))
	require.NoError(t, err)
	err = builder.Add(b)
	require.NoError(t, err)

	d, err := builder.Generate("")
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

func Test_MemResolverQuotesRelativePath(t *testing.T) {
	builder := NewMemResolverConfigBuilder()
	d, err := builder.Generate("./test/relative.jwt")
	require.NoError(t, err)
	conf := string(d)
	require.Contains(t, conf, "operator: \"./test/relative.jwt\"")
}

func Test_MemResolverOperatorPlaceholder(t *testing.T) {
	builder := NewMemResolverConfigBuilder()
	d, err := builder.Generate("--")
	require.NoError(t, err)
	conf := string(d)
	require.Contains(t, conf, "# operator: <specify_path_to_operator_jwt>\n")
}

func Test_MemResolverServerParse(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	opjwt := filepath.Join(ts.Dir, "operator.jwt")
	serverconf := filepath.Join(ts.Dir, "server.conf")

	_, _, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--config-file", serverconf,
		"--operator-jwt", opjwt)

	require.NoError(t, err)

	var opts server.Options
	require.NoError(t, opts.ProcessConfigFile(serverconf))
}
