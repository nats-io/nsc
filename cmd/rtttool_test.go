package cmd

import (
	"github.com/nats-io/nats-server/v2/server"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func Test_RttTool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("running in windows - looking at output hangs")
	}
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "SYS")

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	oc.SystemAccount = ts.GetAccountPublicKey(t, "SYS")
	oc.OperatorServiceURLs.Add("nats://127.0.0.1:4222")
	token, err := oc.Encode(ts.OperatorKey)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")

	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, _, err = ExecuteCmd(createServerConfigCmd(), "--mem-resolver", "--config-file", serverconf)
	require.NoError(t, err)

	var opts server.Options
	require.NoError(t, opts.ProcessConfigFile(serverconf))

	s, err := server.NewServer(&opts)
	require.NoError(t, err)

	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("Unable to start NATS Server in Go Routine")
	}
	defer s.Shutdown()

	_, stdErr, err := ExecuteCmd(createToolRTTCmd(), "--account", "A", "--user", "a")
	require.NoError(t, err)
	require.Contains(t, stdErr, "round trip time to [nats://127.0.0.1:4222]")
}
