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
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestActivationUtil(t *testing.T) {
	dir := MakeTempDir(t)

	os.Setenv(store.DataHomeEnv, dir)
	_, kp := InitStore(t)

	_, pub, _ := CreateAccount(t)

	export := CreateExport(true, "foo")
	export.Add(CreateExport(false, "bar")...)
	token := CreateActivation(t, pub, kp, export...)

	claim, err := jwt.DecodeActivationClaims(token)
	require.NoError(t, err)

	activationPath := filepath.Join(dir, "activation.jwt")
	err = Write(activationPath, []byte(token))
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createLoadActivationCmd(), "--file", activationPath)
	require.NoError(t, err)

	tokens, err := ListActivations()
	require.NoError(t, err)
	require.Len(t, tokens, 1)

	a, err := ParseActivations(tokens)
	require.NoError(t, err)
	require.Len(t, a, 1)
	require.Equal(t, pub, a[0].Subject)

	labels := ActivationLabels(a)
	require.NoError(t, err)
	require.Len(t, labels, 1)
	require.Contains(t, labels[0], claim.Name)

	claim2, err := LoadActivation(claim.ID)
	require.NoError(t, err)
	require.Equal(t, claim, claim2)
}

func TestParseActivationsNilOnError(t *testing.T) {
	v, err := ParseActivations([]string{"foo"})
	require.NotNil(t, err)
	require.Nil(t, v)
}

func TestListActivationsNone(t *testing.T) {
	dir := MakeTempDir(t)
	os.Setenv(store.DataHomeEnv, dir)
	InitStore(t)
	a, err := ListActivations()
	require.NoError(t, err)
	require.Len(t, a, 0)
}
