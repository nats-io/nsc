// Copyright 2026 The NATS Authors
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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nuid"
	"github.com/stretchr/testify/require"
)

type testPKI struct {
	caCert     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func generateTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCertParsed, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	writePEM := func(name string, typ string, data []byte) string {
		fp := filepath.Join(dir, name)
		buf := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: data})
		require.NoError(t, os.WriteFile(fp, buf, 0600))
		return filepath.ToSlash(fp)
	}
	writeKey := func(name string, key *ecdsa.PrivateKey) string {
		der, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		return writePEM(name, "EC PRIVATE KEY", der)
	}

	pki := testPKI{}
	pki.caCert = writePEM("ca.pem", "CERTIFICATE", caCertDER)

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCertParsed, &srvKey.PublicKey, caKey)
	require.NoError(t, err)
	pki.serverCert = writePEM("server-cert.pem", "CERTIFICATE", srvCertDER)
	pki.serverKey = writeKey("server-key.pem", srvKey)

	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cliTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliCertDER, err := x509.CreateCertificate(rand.Reader, cliTemplate, caCertParsed, &cliKey.PublicKey, caKey)
	require.NoError(t, err)
	pki.clientCert = writePEM("client-cert.pem", "CERTIFICATE", cliCertDER)
	pki.clientKey = writeKey("client-key.pem", cliKey)

	return pki
}

type tlsFixture struct {
	ts       *TestStore
	natsURL  string
	dir      string
	caCert   string
	tlsFlags []string
	nc       *nats.Conn
}

func setupTLSFixture(t *testing.T, tlsFirst bool) *tlsFixture {
	t.Helper()
	pki := generateTestPKI(t)

	ts := NewTestStore(t, "O")

	ts.AddAccount(t, "SYS")
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")

	_, err := ExecuteCmd(createEditOperatorCmd(), "--system-account", "SYS")
	require.NoError(t, err)

	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, err = ExecuteCmd(createServerConfigCmd(), "--nats-resolver", "--config-file", serverconf)
	require.NoError(t, err)

	data, err := os.ReadFile(serverconf)
	require.NoError(t, err)
	dir := ts.AddSubDir(t, "resolver")
	data = bytes.ReplaceAll(data, []byte(`dir: './jwt'`), []byte(fmt.Sprintf(`dir: '%s'`, filepath.ToSlash(dir))))

	handshakeFirst := ""
	if tlsFirst {
		handshakeFirst = "\n  handshake_first: true"
	}
	tlsConf := fmt.Sprintf(`
host: "127.0.0.1"
tls: {
  ca_file: "%s"
  cert_file: "%s"
  key_file: "%s"
  verify: true%s
}
`, pki.caCert, pki.serverCert, pki.serverKey, handshakeFirst)
	data = append(data, tlsConf...)
	err = os.WriteFile(serverconf, data, 0660)
	require.NoError(t, err)

	ports := ts.RunServerWithConfig(t, serverconf)
	require.NotNil(t, ports)
	require.True(t, strings.HasPrefix(ports.Nats[0], "tls://"),
		"expected tls:// url, got %s", ports.Nats[0])

	natsURL := strings.ReplaceAll(ports.Nats[0], "tls://", "nats://")
	_, err = ExecuteCmd(createEditOperatorCmd(),
		"--account-jwt-server-url", natsURL,
		"--service-url", natsURL)
	require.NoError(t, err)

	tlsFlags := []string{"--ca-cert", pki.caCert, "--client-cert", pki.clientCert, "--client-key", pki.clientKey}
	if tlsFirst {
		tlsFlags = append(tlsFlags, "--tls-first")
	}

	// push accounts so user creds are recognized by the server
	_, err = ExecuteCmd(createPushCmd(), slices.Concat([]string{"--all"}, tlsFlags)...)
	require.NoError(t, err)

	creds := ts.KeyStore.CalcUserCredsPath("A", "a")
	opts := []nats.Option{
		nats.UserCredentials(creds),
		nats.RootCAs(pki.caCert),
		nats.ClientCert(pki.clientCert, pki.clientKey),
	}
	if tlsFirst {
		opts = append(opts, nats.TLSHandshakeFirst())
	}
	nc, err := nats.Connect(natsURL, opts...)
	require.NoError(t, err)

	t.Cleanup(func() {
		nc.Close()
		ts.Done(t)
	})

	return &tlsFixture{
		ts:       ts,
		natsURL:  natsURL,
		dir:      dir,
		caCert:   pki.caCert,
		tlsFlags: tlsFlags,
		nc:       nc,
	}
}

func runTLSSubtests(t *testing.T, f *tlsFixture) {
	t.Helper()

	type cmdResult struct {
		CmdOutput
		err error
	}

	t.Run("push", func(t *testing.T) {
		_, err := ExecuteCmd(createPushCmd(), slices.Concat([]string{"--all"}, f.tlsFlags)...)
		require.NoError(t, err)

		// SYS + A
		files, err := filepath.Glob(filepath.Join(f.dir, "*.jwt"))
		require.NoError(t, err)
		require.Len(t, files, 2)
	})

	t.Run("pull", func(t *testing.T) {
		_, err := ExecuteCmd(createPullCmd(), slices.Concat([]string{"--all", "--overwrite-newer"}, f.tlsFlags)...)
		require.NoError(t, err)
	})

	t.Run("pub", func(t *testing.T) {
		subj := nuid.Next()
		ch := make(chan *nats.Msg, 1)
		_, err := f.nc.Subscribe(subj, func(m *nats.Msg) { ch <- m })
		require.NoError(t, err)
		require.NoError(t, f.nc.Flush())

		_, err = ExecuteCmd(GetRootCmd(), slices.Concat([]string{"tool", "pub", subj, "hello"}, f.tlsFlags)...)
		require.NoError(t, err)

		select {
		case m := <-ch:
			require.Equal(t, []byte("hello"), m.Data)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for pub message")
		}
	})

	t.Run("sub", func(t *testing.T) {
		subj := nuid.Next()
		subCh := make(chan cmdResult, 1)
		go func() {
			var r cmdResult
			r.CmdOutput, r.err = ExecuteCmd(GetRootCmd(), slices.Concat([]string{"tool", "sub", "--max-messages", "1", subj}, f.tlsFlags)...)
			subCh <- r
		}()
		f.ts.WaitForClient(t, "nsc_sub", 1, 60*time.Second)
		require.NoError(t, f.nc.Publish(subj, []byte("world")))
		require.NoError(t, f.nc.Flush())

		select {
		case r := <-subCh:
			require.NoError(t, r.err)
			require.Contains(t, r.Out, fmt.Sprintf("received on [%s]: 'world'", subj))
		case <-time.After(15 * time.Second):
			t.Fatal("timed out waiting for sub")
		}
	})

	t.Run("req", func(t *testing.T) {
		subj := nuid.Next()
		reqSub, err := f.nc.Subscribe(subj, func(m *nats.Msg) {
			m.Respond([]byte(strings.ToUpper(string(m.Data))))
		})
		require.NoError(t, err)
		require.NoError(t, f.nc.Flush())

		out, err := ExecuteCmd(GetRootCmd(), slices.Concat([]string{"tool", "req", subj, "ping"}, f.tlsFlags)...)
		require.NoError(t, err)
		require.Contains(t, out.Out, "PING")
		require.NoError(t, reqSub.Unsubscribe())
	})

	t.Run("reply", func(t *testing.T) {
		subj := nuid.Next()
		replyCh := make(chan cmdResult, 1)
		go func() {
			var r cmdResult
			r.CmdOutput, r.err = ExecuteCmd(GetRootCmd(), slices.Concat([]string{"tool", "reply", "--max-messages", "1", subj}, f.tlsFlags)...)
			replyCh <- r
		}()
		f.ts.WaitForClient(t, "nsc_reply", 1, 60*time.Second)

		resp, err := f.nc.Request(subj, []byte("test"), 15*time.Second)
		require.NoError(t, err)
		require.Equal(t, "test", string(resp.Data))

		select {
		case r := <-replyCh:
			require.NoError(t, r.err)
		case <-time.After(15 * time.Second):
			t.Fatal("timed out waiting for reply")
		}
	})
}

func Test_TLS(t *testing.T) {
	for _, tc := range []struct {
		name     string
		tlsFirst bool
	}{
		{"standard", false},
		{"handshake_first", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setupTLSFixture(t, tc.tlsFirst)

			t.Run("tls_required", func(t *testing.T) {
				// server has verify: true, so omitting client certs must fail
				args := []string{"--all", "--ca-cert", f.caCert}
				if tc.tlsFirst {
					args = append(args, "--tls-first")
				}
				_, err := ExecuteCmd(createPushCmd(), args...)
				require.Error(t, err)
			})

			runTLSSubtests(t, f)
		})
	}
}
