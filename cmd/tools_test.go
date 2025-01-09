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
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nuid"
	"github.com/stretchr/testify/require"
)

func TestPub(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	// create the basic configuration
	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, err := ExecuteCmd(createServerConfigCmd(), []string{"--mem-resolver",
		"--config-file", serverconf}...)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, serverconf)

	// with the captured ports, regenerate the operator jwt
	// we only need the client to update
	_, err = ExecuteCmd(createEditOperatorCmd(), []string{"--service-url", strings.Join(ports.Nats, ",")}...)
	require.NoError(t, err)

	// create a conn to the server
	nc, err := nats.Connect(strings.Join(ports.Nats, ","),
		nats.UserCredentials(ts.KeyStore.CalcUserCredsPath("A", "U")))
	require.NoError(t, err)
	defer nc.Close()

	// generate a random subject/payload
	v := nuid.Next()
	c := make(chan *nats.Msg)
	_, err = nc.Subscribe(v, func(m *nats.Msg) {
		c <- m
	})
	require.NoError(t, err)
	require.NoError(t, nc.Flush())

	// pub a message
	_, err = ExecuteCmd(createPubCmd(), []string{v, v}...)
	require.NoError(t, err)

	control := <-c
	require.NotNil(t, control)
	require.Equal(t, control.Subject, v)
	require.Equal(t, []byte(v), control.Data)
}

func TestPubPermissionViolation(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	// generate a random subject/payload
	v := nuid.Next()

	ts.AddUser(t, "A", "U")
	_, err := ExecuteCmd(createEditUserCmd(), []string{"--deny-pub", v}...)
	require.NoError(t, err)

	// create the basic configuration
	serverconf := filepath.Join(ts.Dir, "server.conf")
	_, err = ExecuteCmd(createServerConfigCmd(), []string{"--mem-resolver",
		"--config-file", serverconf}...)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, serverconf)

	// with the captured ports, regenerate the operator jwt
	// we only need the client to update
	_, err = ExecuteCmd(createEditOperatorCmd(), []string{"--service-url", strings.Join(ports.Nats, ",")}...)
	require.NoError(t, err)

	// create a conn to the server
	nc, err := nats.Connect(strings.Join(ports.Nats, ","),
		nats.UserCredentials(ts.KeyStore.CalcUserCredsPath("A", "U")))
	require.NoError(t, err)
	defer nc.Close()

	// pub a message
	_, err = ExecuteCmd(createPubCmd(), []string{v, v}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Permissions Violation")
}

func TestSub(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	// create the basic configuration
	conf := filepath.Join(ts.Dir, "server.conf")
	_, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--config-file", conf)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, conf)

	// with the captured ports, regenerate the operator jwt - we only need the client to update
	_, err = ExecuteCmd(createEditOperatorCmd(),
		"--service-url", strings.Join(ports.Nats, ","))
	require.NoError(t, err)

	// generate a random subject/payload
	v := nuid.Next()

	log.SetFlags(log.LstdFlags)
	// subscribe a message
	type po struct {
		CmdOutput
		err error
	}
	c := make(chan po)
	go func() {
		var r po
		r.CmdOutput, r.err = ExecuteCmd(createSubCmd(), "--max-messages", "1", v)
		c <- r
	}()

	// wait for client
	ts.WaitForClient(t, "nsc_sub", 1, 60*time.Second)

	// create a conn to the server
	creds := ts.KeyStore.CalcUserCredsPath("A", "U")
	nc := ts.CreateClient(t, nats.UserCredentials(creds))
	require.NoError(t, nc.Flush())
	err = nc.Publish(v, []byte(v))
	require.NoError(t, err)
	require.NoError(t, nc.Flush())

	select {
	case r := <-c:
		require.NoError(t, r.err)
		require.Contains(t, r.Out, fmt.Sprintf("received on [%s]: '%s'", v, v))
	case <-time.After(25 * time.Second):
		t.Fatal("timed out")
	}
}

func TestSubPermissionViolation(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	// generate a random subject/payload
	v := nuid.Next()

	ts.AddUser(t, "A", "U")
	_, err := ExecuteCmd(createEditUserCmd(), []string{"--deny-sub", v}...)
	require.NoError(t, err)

	// create the basic configuration
	conf := filepath.Join(ts.Dir, "server.conf")
	_, err = ExecuteCmd(createServerConfigCmd(), []string{"--mem-resolver",
		"--config-file", conf}...)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, conf)

	// with the captured ports, regenerate the operator jwt - we only need the client to update
	_, err = ExecuteCmd(createEditOperatorCmd(), []string{"--service-url", strings.Join(ports.Nats, ",")}...)
	require.NoError(t, err)

	log.SetFlags(log.LstdFlags)

	_, err = ExecuteCmd(createSubCmd(), []string{"--max-messages", "1", v}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Permissions Violation")
}

func TestReq(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	// create the basic configuration
	conf := filepath.Join(ts.Dir, "server.conf")

	_, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--config-file", conf)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, conf)

	// with the captured ports, regenerate the operator jwt - we only need the client to update
	_, err = ExecuteCmd(createEditOperatorCmd(),
		"--service-url", strings.Join(ports.Nats, ","))
	require.NoError(t, err)

	// generate a random subject/payload
	v := nuid.Next()

	// create a conn to the server
	creds := ts.KeyStore.CalcUserCredsPath("A", "U")
	nc := ts.CreateClient(t, nats.UserCredentials(creds))
	require.NoError(t, nc.Flush())
	sub, err := nc.Subscribe(v, func(m *nats.Msg) {
		require.NotEmpty(t, m.Reply)
		// reply with the payload in uppercase
		require.NoError(t, m.Respond([]byte(strings.ToUpper(string(m.Data)))))
	})
	require.NoError(t, err)
	require.NoError(t, sub.AutoUnsubscribe(1))
	require.NoError(t, nc.Flush())

	out, err := ExecuteCmd(createToolReqCmd(), v, v)
	require.NoError(t, err)
	require.Contains(t, out.Out, strings.ToUpper(v))
}

func TestReply(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	// create the basic configuration
	conf := filepath.Join(ts.Dir, "server.conf")
	_, err := ExecuteCmd(createServerConfigCmd(), []string{"--mem-resolver",
		"--config-file", conf}...)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, conf)

	// with the captured ports, regenerate the operator jwt - we only need the client to update
	_, err = ExecuteCmd(createEditOperatorCmd(), []string{"--service-url", strings.Join(ports.Nats, ",")}...)
	require.NoError(t, err)

	// generate a random subject/payload
	v := nuid.Next()

	// subscribe a message
	type po struct {
		CmdOutput
		err error
	}
	c := make(chan po)
	go func() {
		var r po
		r.CmdOutput, r.err = ExecuteCmd(createReplyCmd(), []string{"--max-messages", "1", v}...)
		c <- r
	}()

	// wait for client
	ts.WaitForClient(t, "nsc_reply", 1, 60*time.Second)

	// create a conn to the server
	creds := ts.KeyStore.CalcUserCredsPath("A", "U")
	nc := ts.CreateClient(t, nats.UserCredentials(creds))
	require.NoError(t, nc.Flush())

	m, err := nc.Request(v, []byte(v), 15*time.Second)
	require.NoError(t, err)
	require.Equal(t, v, string(m.Data))
}

func TestReplyPermissionViolation(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	// generate a random subject/payload
	v := nuid.Next()

	ts.AddUser(t, "A", "U")
	_, err := ExecuteCmd(createEditUserCmd(), []string{"--deny-sub", v}...)
	require.NoError(t, err)

	// create the basic configuration
	conf := filepath.Join(ts.Dir, "server.conf")
	_, err = ExecuteCmd(createServerConfigCmd(), []string{"--mem-resolver",
		"--config-file", conf}...)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, conf)

	// with the captured ports, regenerate the operator jwt - we only need the client to update
	_, err = ExecuteCmd(createEditOperatorCmd(), []string{"--service-url", strings.Join(ports.Nats, ",")}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createReplyCmd(), []string{"--max-messages", "1", v}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Permissions Violation")
}

func Test_EncryptDecrypt(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	k := ts.GetOperatorPublicKey(t)
	text := "this is a test"
	et, err := Encrypt(k, []byte(text))
	require.NoError(t, err)
	od, err := Decrypt(k, et)
	require.NoError(t, err)
	require.Equal(t, text, string(od))
}
