/*
 * Copyright 2018 The NATS Authors
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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type CmdTest struct {
	cmd        *cobra.Command
	args       []string
	hasOutput  []string
	hasError   []string
	shouldFail bool
}

func BuildChain(commands []string, cmd *cobra.Command) *cobra.Command {
	var root *cobra.Command
	var current *cobra.Command
	for _, n := range commands {
		c := &cobra.Command{
			Use:  n,
			Args: cobra.NoArgs,
		}
		if current != nil {
			current.AddCommand(c)
		}
		current = c
		if root == nil {
			root = current
		}

	}
	current.AddCommand(cmd)
	return root
}

type CmdTests []CmdTest

func (cts *CmdTests) Run(t *testing.T, chain ...string) {
	for i, v := range *cts {
		v.RunTest(t, chain, i)
	}
}

func (c *CmdTest) String() string {
	return strings.Join(c.args, " ")
}

func (c *CmdTest) RunTest(t *testing.T, chain []string, index int) {
	root := BuildChain(chain, c.cmd)
	stdout, stderr, err := ExecuteCmd(root, c.args...)
	for _, v := range c.hasOutput {
		if !strings.Contains(stdout, v) {
			t.Fatalf("%d command '%v' stdout doesn't have %q\nstdout:\n%s\nstderr:\n%s\n", index, c, v, stdout, stderr)
		}
	}
	for _, v := range c.hasError {
		if !strings.Contains(stderr, v) {
			t.Fatalf("%d command '%v' stderr doesn't have %q\nstdout:\n%s\nstderr:\n%s\n", index, c, v, stdout, stderr)
		}
	}
	if c.shouldFail && err == nil {
		t.Fatalf("%d command '%v' should have failed but didn't\nstdout:\n%s\nstderr:\n%s\n", index, c, stdout, stderr)
	}
	if !c.shouldFail && err != nil {
		t.Fatalf("%d command '%v' should have not failed: %v", index, c, err)
	}
}

func ExecuteCmd(root *cobra.Command, args ...string) (stdout string, stderr string, err error) {
	var stderrBuf, stdoutBuf bytes.Buffer
	root.SetOutput(&stderrBuf)
	root.SetArgs(args)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, err = root.ExecuteC()

	w.Close()
	os.Stdout = old
	io.Copy(&stdoutBuf, r)

	return stdoutBuf.String(), stderrBuf.String(), err
}

func MakeTempDir(t *testing.T) string {
	p, err := ioutil.TempDir("", "ngs_cli_test")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func CreateUser(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateUser)
}

func CreateAccount(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateAccount)
}

func CreateOperator(t *testing.T) (seed []byte, pub string, kp nkeys.KeyPair) {
	return CreateNkey(t, nkeys.CreateOperator)
}

type NKeyFactory func() (nkeys.KeyPair, error)

func CreateNkey(t *testing.T, f NKeyFactory) ([]byte, string, nkeys.KeyPair) {
	kp, err := f()
	if err != nil {
		t.Fatal(err)
	}

	seed, err := kp.Seed()
	if err != nil {
		t.Fatal(err)
	}

	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return seed, string(pub), kp
}

func InitStore(t *testing.T) (*store.Store, nkeys.KeyPair) {
	// reset the store - across test the first
	// command will initialize - each test should
	// get it's own store.
	ngsStore = nil

	_, pub, kp := CreateAccount(t)
	s, err := store.CreateStore("", "", pub)
	if err != nil {
		t.Fatal(err)
	}
	_, _, okp := CreateOperator(t)

	ac := jwt.NewActivationClaims(pub)
	ac.Expires = time.Now().AddDate(0, 0, 1).Unix()
	token, err := ac.Encode(okp)
	if err != nil {
		t.Fatal(err)
	}
	s.SetAccountActivation(token)
	return s, kp
}

func SeedKey(t *testing.T, kp nkeys.KeyPair) string {
	d, err := kp.Seed()
	require.NoError(t, err)
	return string(d)
}

func PublicKey(t *testing.T, kp nkeys.KeyPair) string {
	d, err := kp.PublicKey()
	require.NoError(t, err)
	return string(d)
}

func (p *AddUserParams) AsArgs() []string {
	var args []string
	if p.publicKey != "" {
		args = append(args, "--public-key", p.publicKey)
	}
	if p.name != "" {
		args = append(args, "--name", p.name)
	}
	if p.tags != nil {
		args = append(args, "--tag", strings.Join(p.tags, ","))
	}
	if p.allowPubs != nil {
		args = append(args, "--allow-pub", strings.Join(p.allowPubs, ","))
	}
	if p.allowSubs != nil {
		args = append(args, "--allow-sub", strings.Join(p.allowSubs, ","))
	}
	if p.allowPubsub != nil {
		args = append(args, "--allow-pubsub", strings.Join(p.allowPubsub, ","))
	}
	if p.denyPubs != nil {
		args = append(args, "--deny-pub", strings.Join(p.denyPubs, ","))
	}
	if p.denySubs != nil {
		args = append(args, "--deny-sub", strings.Join(p.denySubs, ","))
	}
	if p.denyPubsub != nil {
		args = append(args, "--deny-pubsub", strings.Join(p.denyPubsub, ","))
	}

	if p.max != "" {
		args = append(args, "--max-messages", p.max)
	}
	if p.payload != "" {
		args = append(args, "--max-payload", p.payload)
	}
	if p.src != nil {
		args = append(args, "--source-network", strings.Join(p.src, ","))
	}
	if p.generate {
		args = append(args, "--generate-nkeys")
	}
	if p.outputFile != "" {
		args = append(args, "--output-file", p.outputFile)
	}
	return args
}

func CreateUserParams(t *testing.T, name string) *AddUserParams {
	_, pub, _ := CreateUser(t)
	up := AddUserParams{}
	up.name = name
	up.publicKey = pub
	up.allowPubs = A("a", "b")
	up.allowSubs = A("c", "d")
	up.allowPubsub = A("e", "f")

	up.denyPubs = A("u", "v")
	up.denySubs = A("w", "x")
	up.denyPubsub = A("y", "z")

	up.tags = A("t1", "t2")
	up.max = "10K"
	up.payload = "1M"
	up.src = A("192.168.1.0/32")

	return &up
}

func AddUserFromParams(t *testing.T, p *AddUserParams) {
	_, _, err := ExecuteCmd(createAddUserCmd(), p.AsArgs()...)
	if err != nil {
		t.Fatal("error adding user", err)
	}
}

func EditUser(t *testing.T, pk string, flags ...string) *User {
	flags = append(flags, "-k", pk)
	_, _, err := ExecuteCmd(createEditUserCmd(), flags...)
	require.NoError(t, err)

	u := User{}
	u.PublicKey = pk
	err = u.Load()
	require.NoError(t, err)

	return &u
}

func AddUser(t *testing.T, pk string, flags ...string) *User {
	flags = append(flags, "-k", pk)
	_, _, err := ExecuteCmd(createAddUserCmd(), flags...)
	require.NoError(t, err)

	u := User{}
	u.PublicKey = pk
	err = u.Load()
	require.NoError(t, err)

	return &u
}

func CreateActivation(t *testing.T, subject string, owner nkeys.KeyPair, export ...jwt.Export) string {
	if subject == "" {
		subject = "public"
	}
	if owner == nil {
		_, _, owner = CreateAccount(t)
	}

	act := jwt.NewActivationClaims(subject)
	act.Expires = time.Now().AddDate(0, 1, 0).Unix()
	act.Name = fmt.Sprintf("Test Activation - %s", subject)
	act.Exports.Add(export...)

	v, err := act.Encode(owner)
	if err != nil {
		t.Fatal("error encoding activation", err)
	}
	return v
}

func CreateStreamActivation(t *testing.T, subject string, owner nkeys.KeyPair, stream ...string) string {
	return CreateActivation(t, subject, owner, CreateExport(false, stream...)...)

}

func CreateServiceActivation(t *testing.T, subject string, owner nkeys.KeyPair, service ...string) string {
	return CreateActivation(t, subject, owner, CreateExport(true, service...)...)
}

func CreateExport(service bool, subject ...string) jwt.Exports {
	serviceType := jwt.StreamType
	if service {
		serviceType = jwt.ServiceType
	}
	var exports jwt.Exports
	for _, v := range subject {
		s := jwt.Export{}
		s.Name = strings.ToUpper(v + " " + serviceType)
		s.Subject = jwt.Subject(v)
		s.Type = serviceType
		exports.Add(s)
	}
	return exports
}

func CreateExpiringActivation(t *testing.T, subject string, owner nkeys.KeyPair) string {
	if subject == "" {
		subject = "public"
	}
	if owner == nil {
		_, _, owner = CreateAccount(t)
	}

	act := jwt.NewActivationClaims(subject)
	act.Expires = time.Now().Unix()
	act.Name = fmt.Sprintf("Test Activation - %s", subject)

	s := jwt.Export{}
	s.Subject = "foo.bar"
	s.Type = jwt.StreamType
	act.Exports.Add(s)

	v, err := act.Encode(owner)
	if err != nil {
		t.Fatal("error encoding activation", err)
	}
	return v
}

func A(s ...string) []string {
	return s
}
