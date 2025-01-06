/*
 * Copyright 2025-2025 The NATS Authors
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
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
	"testing"
)

func buildDiagreamStore(t *testing.T, ts *TestStore) {
	ts.AddAccount(t, "A")
	ts.AddExport(t, "A", jwt.Stream, "a", 0, true)
	ts.AddExport(t, "A", jwt.Service, "q", 0, true)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	_, pub, _ := CreateAccountKey(t)
	ac.SigningKeys.Add(pub)

	ac.DefaultPermissions.Pub.Allow.Add("a.hello")
	ac.DefaultPermissions.Pub.Deny.Add("a.bye")
	ac.DefaultPermissions.Sub.Allow.Add("a.hi")
	ac.DefaultPermissions.Sub.Allow.Add("a.goodbye")

	token, err := ac.Encode(ts.OperatorKey)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	ts.AddAccount(t, "B")
	ts.AddImport(t, "A", jwt.Stream, "a", "B")
	ts.AddImport(t, "A", jwt.Service, "q", "B")
	ts.AddUser(t, "B", "b")

	uc, err := ts.Store.ReadUserClaim("B", "b")
	require.NoError(t, err)
	uc.Permissions.Pub.Allow.Add("a.>")
	uc.Permissions.Pub.Deny.Add("b.>")
	uc.Permissions.Sub.Allow.Add("a.>")
	uc.Permissions.Sub.Deny.Add("b.>")
	token, err = uc.Encode(ts.GetAccountKey(t, "B"))
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))
}

func Test_ObjectDiagram(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	buildDiagreamStore(t, ts)

	out, err := ExecuteCmd(createObjectDiagramCmd(), "--show-keys", "--users", "--detail")
	require.NoError(t, err)
	require.Contains(t, out.Out, "@startuml")
	require.Contains(t, out.Out, "object \"O\" as")
	require.Contains(t, out.Out, "object \"A\" as")
	require.Contains(t, out.Out, "object \"B\" as")
	require.Contains(t, out.Out, "object \"b\" as")
	require.Contains(t, out.Out, "@enduml")
}

func Test_ComponentDiagram(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	buildDiagreamStore(t, ts)

	out, err := ExecuteCmd(createComponentDiagreamCmd(), []string{"--detail"}...)
	require.NoError(t, err)

	require.Contains(t, out.Out, "@startuml")
	require.Contains(t, out.Out, "Component Diagram of Accounts - Operator O")
	require.Contains(t, out.Out, "component [A]")
	require.Contains(t, out.Out, "component [B]")
	require.Contains(t, out.Out, "\"a\" << public stream >>")
	require.Contains(t, out.Out, "\"q\" << public service >>")
	require.Contains(t, out.Out, "@enduml")
}
