package cmd

import (
	"github.com/stretchr/testify/require"
	"path/filepath"
	"runtime"
	"testing"
)

func Test_FlagTable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("running in windows - looking at output hangs")
	}
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	stdout, _, err := ExecuteCmd(GetRootCmd(), "test", "flags")
	require.NoError(t, err)
	require.Contains(t, stdout, "nsc validate")
	require.Contains(t, stdout, "nsc add account")
}

func Test_WhoFlagTable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("running in windows - looking at output hangs")
	}
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	stdout, _, err := ExecuteCmd(GetRootCmd(), "test", "whoflag", "allow-pub")
	require.NoError(t, err)
	require.Contains(t, stdout, "nsc add user")
}

func Test_Doc(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	docs := filepath.Join(ts.Dir, "doc")
	_, _, err := ExecuteCmd(GetRootCmd(), "test", "doc", docs)
	require.NoError(t, err)
	require.DirExists(t, docs)
	require.FileExists(t, filepath.Join(docs, "nsc_add.md"))
	require.FileExists(t, filepath.Join(docs, "nsc_validate.md"))
}
