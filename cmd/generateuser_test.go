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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestGenerateUser(t *testing.T) {
	os.Setenv(store.DataHomeEnv, MakeTempDir(t))
	os.Setenv(store.DataProfileEnv, "test")

	InitStore(t)

	up := CreateUserParams(t, "export")
	AddUserFromParams(t, up)

	tests := CmdTests{
		{createGenerateUserCmd(), []string{"export", "user", "-m", "foo"}, nil, []string{"didn't match anything"}, true},
		{createGenerateUserCmd(), []string{"export", "user", "--public-key", up.publicKey}, []string{"BEGIN USER JWT", "END USER JWT"}, nil, false},
		{createGenerateUserCmd(), []string{"export", "user", "-m", up.publicKey[0:5]}, []string{"BEGIN USER JWT", "END USER JWT"}, nil, false},
		{createGenerateUserCmd(), []string{"export", "user", "-m", up.publicKey, "--json"}, []string{"\"name\": \"export\","}, nil, false},
		{createGenerateUserCmd(), []string{"export", "user", "-m", up.publicKey, "--expiry", "10x"}, nil, []string{"couldn't parse expiry: 10x"}, true},
		{createGenerateUserCmd(), []string{"export", "user", "-m", up.publicKey, "--expiry", "10d"}, nil, nil, false},
	}
	tests.Run(t, "root", "export")
}

func TestGenerateUserJWT(t *testing.T) {
	os.Setenv(store.DataHomeEnv, MakeTempDir(t))
	os.Setenv(store.DataProfileEnv, "test")

	s := InitStore(t)
	apk, err := s.GetPublicKey()

	up := CreateUserParams(t, "testuser")
	AddUserFromParams(t, up)

	exp := time.Now().AddDate(0, 0, 30).Unix()
	stdout, _, err := ExecuteCmd(createGenerateUserCmd(), "-m", "testuser")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(stdout, "\n")
	claim, err := jwt.DecodeUserClaims(lines[1])
	if err != nil {
		t.Fatalf("error decoding claim: %v", err)
	}
	require.Equal(t, apk, claim.Issuer, "issuer")
	require.InDelta(t, exp, claim.Expires, .99999, "expiration")
	require.Equal(t, up.publicKey, claim.ClaimsData.Subject, "claim subject")

	for _, v := range up.allowPubs {
		require.Contains(t, claim.Pub.Allow, v, "pub subjects")
	}
	for _, v := range up.allowPubsub {
		require.Contains(t, claim.Pub.Allow, v, "pub subjects")
	}
	for _, v := range up.denyPubs {
		require.Contains(t, claim.Pub.Deny, v, "deny pub subjects")
	}
	for _, v := range up.denyPubsub {
		require.Contains(t, claim.Pub.Deny, v, "deny pub pubsub subjects")
	}
	for _, v := range up.allowSubs {
		require.Contains(t, claim.Sub.Allow, v, "sub subjects")
	}
	for _, v := range up.allowPubsub {
		require.Contains(t, claim.Sub.Allow, v, "sub subjects")
	}
	for _, v := range up.denySubs {
		require.Contains(t, claim.Sub.Deny, v, "deny sub subjects")
	}
	for _, v := range up.denyPubsub {
		require.Contains(t, claim.Sub.Deny, v, "deny sub pubsub subjects")
	}
}

func TestGenerateUserCustomExpiry(t *testing.T) {
	os.Setenv(store.DataHomeEnv, MakeTempDir(t))
	os.Setenv(store.DataProfileEnv, "test")

	s := InitStore(t)
	apk, err := s.GetPublicKey()

	up := CreateUserParams(t, "testuser")
	AddUserFromParams(t, up)

	exp := time.Now().AddDate(0, 0, 10).Unix()
	stdout, _, err := ExecuteCmd(createGenerateUserCmd(), "-m", "testuser", "-e", "10d")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(stdout, "\n")
	claim, err := jwt.DecodeUserClaims(lines[1])
	if err != nil {
		t.Fatalf("error decoding claim: %v", err)
	}
	require.Equal(t, apk, claim.Issuer, "issuer")
	require.InDelta(t, exp, claim.Expires, .99999, "expiration")
}

func TestGenerateUserNoExpiry(t *testing.T) {
	os.Setenv(store.DataHomeEnv, MakeTempDir(t))
	os.Setenv(store.DataProfileEnv, "test")

	s := InitStore(t)
	apk, err := s.GetPublicKey()

	up := CreateUserParams(t, "testuser")
	AddUserFromParams(t, up)

	stdout, _, err := ExecuteCmd(createGenerateUserCmd(), "-m", "testuser", "-e", "0")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(stdout, "\n")
	claim, err := jwt.DecodeUserClaims(lines[1])
	if err != nil {
		t.Fatalf("error decoding claim: %v", err)
	}
	require.Equal(t, apk, claim.Issuer, "issuer")
	require.Zero(t, claim.Expires, "expiration")
}

func TestGenerateUserJWTFile(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	os.Setenv(store.DataProfileEnv, "test")

	s := InitStore(t)
	apk, err := s.GetPublicKey()

	up := CreateUserParams(t, "testuser")
	AddUserFromParams(t, up)

	outFile := filepath.Join(dir, "token")

	exp := time.Now().AddDate(0, 0, 10).Unix()
	_, _, err = ExecuteCmd(createGenerateUserCmd(), "export", "user", "-m", "testuser", "--expiry", "10d", "--output-file", outFile)
	if err != nil {
		t.Fatal(err)
	}

	d, err := ioutil.ReadFile(outFile)
	if err != nil {
		t.Fatalf("error writing file: %v", err)
	}

	lines := strings.Split(string(d), "\n")
	claim, err := jwt.DecodeUserClaims(lines[1])
	if err != nil {
		t.Fatalf("error decoding claim: %v", err)
	}
	require.Equal(t, apk, claim.Issuer, "issuer")
	require.Equal(t, exp, claim.Expires, "expiration")
	require.Equal(t, up.publicKey, claim.ClaimsData.Subject, "claim subject")
	for _, v := range up.allowPubs {
		require.Contains(t, claim.Pub.Allow, v, "pub subjects")
	}
	for _, v := range up.allowPubsub {
		require.Contains(t, claim.Pub.Allow, v, "pub subjects")
	}
	for _, v := range up.denyPubs {
		require.Contains(t, claim.Pub.Deny, v, "deny pub subjects")
	}
	for _, v := range up.denyPubsub {
		require.Contains(t, claim.Pub.Deny, v, "deny pub pubsub subjects")
	}
	for _, v := range up.allowSubs {
		require.Contains(t, claim.Sub.Allow, v, "sub subjects")
	}
	for _, v := range up.allowPubsub {
		require.Contains(t, claim.Sub.Allow, v, "sub subjects")
	}
	for _, v := range up.denySubs {
		require.Contains(t, claim.Sub.Deny, v, "deny sub subjects")
	}
	for _, v := range up.denyPubsub {
		require.Contains(t, claim.Sub.Deny, v, "deny sub pubsub subjects")
	}
}
