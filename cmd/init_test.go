// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	cli "github.com/nats-io/cliprompts/v2"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func Test_InitLocal(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, err := ExecuteCmd(createInitCmd(), []string{"--name", "O"}...)
	require.NoError(t, err)

	ts.VerifyOperator(t, "O", false)
	ts.VerifyAccount(t, "O", "O", true)
	ts.VerifyUser(t, "O", "O", "O", true)
	ts.VerifyAccount(t, "O", "SYS", true)
	ts.VerifyUser(t, "O", "SYS", "sys", true)
}

func Test_InitExists(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, err := ExecuteCmd(createInitCmd(), []string{"--name", "O"}...)
	require.Error(t, err)
}

func Test_InitDeploy(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	as, _ := RunTestAccountServer(t)
	defer as.Close()

	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	_, err = ExecuteCmd(createInitCmd(), []string{"--name", "O", "--url", ourl.String()}...)
	require.NoError(t, err)

	ts.VerifyOperator(t, "T", true)
	ts.VerifyAccount(t, "T", "O", true)
	ts.VerifyUser(t, "T", "O", "O", true)
}

func Test_InitRandomName(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	as, _ := RunTestAccountServer(t)
	defer as.Close()

	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	_, err = ExecuteCmd(createInitCmd(), []string{"--url", ourl.String()}...)
	require.NoError(t, err)

	name := GetLastRandomName()

	ts.VerifyOperator(t, "T", true) // Operator name comes from the URL
	ts.VerifyAccount(t, "T", name, true)
	ts.VerifyUser(t, "T", name, name, true)
}

func Test_InitStarName(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	as, _ := RunTestAccountServer(t)
	defer as.Close()

	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	_, err = ExecuteCmd(createInitCmd(), []string{"--url", ourl.String(), "-n", "*"}...)
	require.NoError(t, err)

	name := GetLastRandomName()

	ts.VerifyOperator(t, "T", true) // Operator name comes from the URL
	ts.VerifyAccount(t, "T", name, true)
	ts.VerifyUser(t, "T", name, name, true)
}

func Test_InitWellKnown(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	// run a jwt account server
	as, _ := RunTestAccountServer(t)
	defer as.Close()

	// add an entry to well known
	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	var twko KnownOperator
	twko.AccountServerURL = ourl.String()
	twko.Name = "T"

	// make it be the first
	var wkops KnownOperators
	wkops = append(wkops, twko)

	ops, _ := GetWellKnownOperators()
	wkops = append(wkops, ops...)
	wellKnownOperators = wkops

	_, err = ExecuteCmd(createInitCmd(), []string{"--remote-operator", "T", "--name", "A"}...)
	require.NoError(t, err)

	ts.VerifyOperator(t, "T", true)
	ts.VerifyAccount(t, "T", "A", true)
	ts.VerifyUser(t, "T", "A", "A", true)
}

func Test_InitWellKnown2(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	// add an entry to well known
	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	var twko KnownOperator
	twko.AccountServerURL = ourl.String()
	twko.Name = "T"

	// make it be the first
	var wkops KnownOperators
	wkops = append(wkops, twko)

	ops, _ := GetWellKnownOperators()
	wkops = append(wkops, ops...)
	wellKnownOperators = wkops

	// get the managed operator on the first
	_, err = ExecuteCmd(createInitCmd(), []string{"--remote-operator", "T", "--name", "A"}...)
	require.NoError(t, err)

	// now add another account
	_, err = ExecuteCmd(createInitCmd(), []string{"--remote-operator", "T", "--name", "B"}...)
	require.NoError(t, err)

	ts.VerifyOperator(t, "T", true)
	ts.VerifyAccount(t, "T", "B", true)
	ts.VerifyUser(t, "T", "B", "B", true)
}

func Test_InitWellKnownV1Operator(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	_, _, okp := CreateOperatorKey(t)
	// run a jwt account server
	as, _ := RunTestAccountServerWithOperatorKP(t, okp, TasOpts{Vers: 1})
	defer as.Close()

	// add an entry to well known
	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	var twko KnownOperator
	twko.AccountServerURL = ourl.String()
	twko.Name = "T"

	// make it be the first
	var wkops KnownOperators
	wkops = append(wkops, twko)

	ops, _ := GetWellKnownOperators()
	wkops = append(wkops, ops...)
	wellKnownOperators = wkops

	_, err = ExecuteCmd(createInitCmd(), []string{"--remote-operator", "T", "--name", "A"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "the operator jwt (v1) is incompatible this version of nsc")
}

func Test_InitWellKnownInteractive(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	// add an entry to well known
	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	var twko KnownOperator
	twko.AccountServerURL = ourl.String()
	twko.Name = "T"

	// make it be the first
	var wkops KnownOperators
	wkops = append(wkops, twko)

	ops, _ := GetWellKnownOperators()
	wkops = append(wkops, ops...)
	wellKnownOperators = wkops

	_, err = ExecuteInteractiveCmd(createInitCmd(), []interface{}{ts.GetStoresRoot(), 0, "A"})
	require.NoError(t, err)

	ts.VerifyOperator(t, "T", true)
	ts.VerifyAccount(t, "T", "A", true)
	ts.VerifyUser(t, "T", "A", "A", true)
}

func Test_InitLocalInteractive(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	cli.LogFn = t.Log
	_, err := ExecuteInteractiveCmd(createInitCmd(), []interface{}{ts.GetStoresRoot(), 1, "O"})
	require.NoError(t, err)

	ts.VerifyOperator(t, "O", false)
	ts.VerifyAccount(t, "O", "O", true)
	ts.VerifyUser(t, "O", "O", "O", true)
	ts.VerifyAccount(t, "O", "SYS", true)
	ts.VerifyUser(t, "O", "SYS", "sys", true)
}

func Test_InitCustomInteractive(t *testing.T) {
	ts := NewTestStore(t, "X")
	defer ts.Done(t)

	// run a jwt account server
	as, _ := RunTestAccountServer(t)
	defer as.Close()

	// add an entry to well known
	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"

	_, err = ExecuteInteractiveCmd(createInitCmd(), []interface{}{ts.GetStoresRoot(), 2, ourl.String(), "A"})
	require.NoError(t, err)

	ts.VerifyOperator(t, "T", true)
	ts.VerifyAccount(t, "T", "A", true)
	ts.VerifyUser(t, "T", "A", "A", true)
}

func Test_InitDuplicate(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ourl, err := url.Parse(as.URL)
	require.NoError(t, err)
	ourl.Path = "/jwt/v1/operator"
	u := ourl.String()

	// get the managed operator on the first
	_, err = ExecuteCmd(createInitCmd(), []string{"--url", u, "--name", "A"}...)
	require.NoError(t, err)

	ts.VerifyOperator(t, "T", true)
	ts.VerifyAccount(t, "T", "A", true)
	ts.VerifyUser(t, "T", "A", "A", true)

	// try to do it again with the same name
	_, err = ExecuteCmd(createInitCmd(), []string{"--url", u, "--name", "A"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "an account named \"A\" already exists")
}
