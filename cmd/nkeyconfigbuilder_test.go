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
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func Test_NkeyResolverBasicProperties(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "ua")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "ub")

	builder := NewNKeyConfigBuilder()

	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	uac, err := ts.Store.ReadUserClaim("A", "ua")
	require.NoError(t, err)
	ua, err := ts.Store.Read(store.Accounts, "A", store.Users, store.JwtName("ua"))
	require.NoError(t, err)
	err = builder.Add(ua)
	require.NoError(t, err)

	b, err := ts.Store.Read(store.Accounts, "B", store.JwtName("B"))
	require.NoError(t, err)
	err = builder.Add(b)
	require.NoError(t, err)

	ubc, err := ts.Store.ReadUserClaim("B", "ub")
	require.NoError(t, err)
	ub, err := ts.Store.Read(store.Accounts, "B", store.Users, store.JwtName("ub"))
	require.NoError(t, err)
	err = builder.Add(ub)
	require.NoError(t, err)

	d, err := builder.Generate()
	require.NoError(t, err)

	conf := string(d)
	conf = strings.ReplaceAll(conf, " ", "")
	conf = strings.ReplaceAll(conf, "\n", "")

	require.Contains(t, conf, "accounts:{")
	require.Contains(t, conf, fmt.Sprintf("A:{users:[{nkey:%s}]}", uac.Subject))
	require.Contains(t, conf, fmt.Sprintf("B:{users:[{nkey:%s}]}", ubc.Subject))
}

func Test_NkeyResolverExportsStreamsServices(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "service.>", true)
	ts.AddExport(t, "A", jwt.Stream, "stream.>", true)

	builder := NewNKeyConfigBuilder()

	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	d, err := builder.Generate()
	require.NoError(t, err)

	conf := string(d)
	conf = strings.ReplaceAll(conf, " ", "")
	conf = strings.ReplaceAll(conf, "\n", "")

	require.Contains(t, conf, "accounts:{A:{exports:[")
	require.Contains(t, conf, "{service:service.>}")
	require.Contains(t, conf, "{stream:stream.>}")
}

func Test_NkeyResolverExportsPrivateStreamsServices(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "service.>", false)
	ts.AddExport(t, "A", jwt.Stream, "stream.>", false)

	builder := NewNKeyConfigBuilder()

	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	d, err := builder.Generate()
	require.NoError(t, err)

	conf := string(d)
	conf = strings.ReplaceAll(conf, " ", "")
	conf = strings.ReplaceAll(conf, "\n", "")

	require.Contains(t, conf, "accounts:{A:{exports:[")
	require.Contains(t, conf, "{service:service.>,accounts:[]}")
	require.Contains(t, conf, "{stream:stream.>,accounts:[]}")
}

func Test_NkeyResolverMapsImporter(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Service, "service.b", false)
	ts.AddExport(t, "A", jwt.Stream, "stream.a", false)

	ts.AddAccount(t, "B")

	ts.AddImport(t, "A", "service.b", "B")
	ts.AddImport(t, "A", "stream.a", "B")

	builder := NewNKeyConfigBuilder()

	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	b, err := ts.Store.Read(store.Accounts, "B", store.JwtName("B"))
	require.NoError(t, err)
	err = builder.Add(b)
	require.NoError(t, err)

	d, err := builder.Generate()
	require.NoError(t, err)

	conf := string(d)

	conf = strings.ReplaceAll(conf, " ", "")
	conf = strings.ReplaceAll(conf, "\n", "")

	require.Contains(t, conf, "{service:service.b,accounts:[B]}")
	require.Contains(t, conf, "{stream:stream.a,accounts:[B]}")

	require.Contains(t, conf, "{service:{account:A,subject:service.b},to:service.b}")
	require.Contains(t, conf, "{stream:{account:A,subject:stream.a}}")
}

func Test_NkeyResolverAddsSigningKeyUser(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, pk, sk := CreateAccountKey(t)
	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	ac.SigningKeys.Add(pk)
	token, err := ac.Encode(sk)
	require.NoError(t, err)
	rs, err := ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)
	require.Nil(t, rs)

	ts.AddUserWithSigner(t, "A", "ua", sk)

	builder := NewNKeyConfigBuilder()

	a, err := ts.Store.Read(store.Accounts, "A", store.JwtName("A"))
	require.NoError(t, err)
	err = builder.Add(a)
	require.NoError(t, err)

	ua, err := ts.Store.Read(store.Accounts, "A", store.Users, store.JwtName("ua"))
	require.NoError(t, err)
	require.NoError(t, builder.Add(ua))
	uc, err := ts.Store.ReadUserClaim("A", "ua")
	require.NoError(t, err)

	d, err := builder.Generate()
	require.NoError(t, err)

	conf := string(d)
	conf = strings.ReplaceAll(conf, " ", "")
	conf = strings.ReplaceAll(conf, "\n", "")

	require.Contains(t, conf, "accounts:{")
	require.Contains(t, conf, fmt.Sprintf("accounts:{A:{users:[{nkey:%s}]}", uc.Subject))
}
