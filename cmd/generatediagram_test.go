package cmd

import (
	"runtime"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
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
	if runtime.GOOS == "windows" {
		t.Skip("running in windows - looking at output hangs")
	}
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	buildDiagreamStore(t, ts)

	stdOut, _, err := ExecuteCmd(createObjectDiagramCmd(), "--show-keys", "--users", "--detail")
	require.NoError(t, err)
	require.Contains(t, stdOut, "@startuml")
	require.Contains(t, stdOut, "object \"O\" as")
	require.Contains(t, stdOut, "object \"A\" as")
	require.Contains(t, stdOut, "object \"B\" as")
	require.Contains(t, stdOut, "object \"b\" as")
	require.Contains(t, stdOut, "@enduml")
}

func Test_ComponentDiagram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("running in windows - looking at output hangs")
	}
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	buildDiagreamStore(t, ts)

	stdOut, _, err := ExecuteCmd(createComponentDiagreamCmd(), "--detail")
	require.NoError(t, err)

	require.Contains(t, stdOut, "@startuml")
	require.Contains(t, stdOut, "Component Diagram of Accounts - Operator O")
	require.Contains(t, stdOut, "component [A]")
	require.Contains(t, stdOut, "component [B]")
	require.Contains(t, stdOut, "\"a\" << public stream >>")
	require.Contains(t, stdOut, "\"q\" << public service >>")
	require.Contains(t, stdOut, "@enduml")
}
