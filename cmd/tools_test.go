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
	opjwt := filepath.Join(ts.Dir, "operator.jwt")
	serverconf := filepath.Join(ts.Dir, "server.conf")

	_, _, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--config-file", serverconf,
		"--operator-jwt", opjwt)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, serverconf)

	// with the captured ports, regenerate the operator jwt
	// we only need the client to update
	_, _, err = ExecuteCmd(createEditOperatorCmd(),
		"--service-url", strings.Join(ports.Nats, ","))
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
	_, _, err = ExecuteCmd(createPubCmd(), v, v)
	require.NoError(t, err)

	control := <-c
	require.NotNil(t, control)
	require.Equal(t, control.Subject, v)
	require.Equal(t, []byte(v), control.Data)
}

func TestSub(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	// create the basic configuration
	op := filepath.Join(ts.Dir, "operator.jwt")
	conf := filepath.Join(ts.Dir, "server.conf")

	_, _, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--config-file", conf,
		"--operator-jwt", op)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, conf)

	// with the captured ports, regenerate the operator jwt - we only need the client to update
	_, _, err = ExecuteCmd(createEditOperatorCmd(),
		"--service-url", strings.Join(ports.Nats, ","))
	require.NoError(t, err)

	// generate a random subject/payload
	v := nuid.Next()

	log.SetFlags(log.LstdFlags)
	// subscribe a message
	type po struct {
		stdout string
		stderr string
		err    error
	}
	c := make(chan po)
	go func() {
		var r po
		r.stdout, r.stderr, r.err = ExecuteCmd(createSubCmd(), "--max-messages", "1", v)
		c <- r
	}()

	// wait for client
	ts.WaitForClient(t, "nscsub", 1, 60*time.Second)

	// create a conn to the server
	creds := ts.KeyStore.CalcUserCredsPath("A", "U")
	nc := ts.CreateClient(t, nats.UserCredentials(creds))
	require.NoError(t, nc.Flush())
	err = nc.Publish(v, []byte(v))
	require.NoError(t, err)
	require.NoError(t, nc.Flush())

	select {
	case r := <-c:
		t.Log(r.stdout)
		t.Log(r.stderr)
		t.Log(r.err)
		require.NoError(t, r.err)
		require.Contains(t, r.stderr, fmt.Sprintf("Received on [%s]: '%s'", v, v))
	case <-time.After(25 * time.Second):
		t.Fatal("timed out")
	}
}

func TestReq(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	// create the basic configuration
	op := filepath.Join(ts.Dir, "operator.jwt")
	conf := filepath.Join(ts.Dir, "server.conf")

	_, _, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--config-file", conf,
		"--operator-jwt", op)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, conf)

	// with the captured ports, regenerate the operator jwt - we only need the client to update
	_, _, err = ExecuteCmd(createEditOperatorCmd(),
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

	_, stderr, err := ExecuteCmd(createToolReqCmd(), v, v)
	require.NoError(t, err)
	require.Contains(t, stderr, strings.ToUpper(v))
}

func TestReply(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	// create the basic configuration
	op := filepath.Join(ts.Dir, "operator.jwt")
	conf := filepath.Join(ts.Dir, "server.conf")

	_, _, err := ExecuteCmd(createServerConfigCmd(), "--mem-resolver",
		"--config-file", conf,
		"--operator-jwt", op)
	require.NoError(t, err)

	// start a server with the config at a random port
	ports := ts.RunServerWithConfig(t, conf)

	// with the captured ports, regenerate the operator jwt - we only need the client to update
	_, _, err = ExecuteCmd(createEditOperatorCmd(),
		"--service-url", strings.Join(ports.Nats, ","))
	require.NoError(t, err)

	// generate a random subject/payload
	v := nuid.Next()

	// subscribe a message
	type po struct {
		stdout string
		stderr string
		err    error
	}
	c := make(chan po)
	go func() {
		var r po
		r.stdout, r.stderr, r.err = ExecuteCmd(createReplyCmd(), "--max-messages", "1", v)
		c <- r
	}()

	// wait for client
	ts.WaitForClient(t, "nscreply", 1, 60*time.Second)

	// create a conn to the server
	creds := ts.KeyStore.CalcUserCredsPath("A", "U")
	nc := ts.CreateClient(t, nats.UserCredentials(creds))
	require.NoError(t, nc.Flush())

	m, err := nc.Request(v, []byte(v), 15*time.Second)
	require.NoError(t, err)
	require.Equal(t, v, string(m.Data))
}
