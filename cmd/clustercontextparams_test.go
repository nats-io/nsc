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
	"testing"

	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestCCP_DefaultsInit(t *testing.T) {
	ts := NewTestStore(t, "ccp")
	defer ts.Done(t)

	ts.AddCluster(t, "foo")
	ctx, err := NewActx(nil, nil)
	require.NoError(t, err)

	ccp := ClusterContextParams{}
	ccp.SetDefaults(ctx)
	require.Equal(t, "foo", ccp.Name)
}

func TestCCP_DefaultsSelectsArg(t *testing.T) {
	ts := NewTestStore(t, "ccp")
	defer ts.Done(t)

	ts.AddCluster(t, "foo")
	ctx, err := NewActx(nil, nil)
	require.NoError(t, err)

	ccp := ClusterContextParams{}
	ccp.Name = "bar"
	ccp.SetDefaults(ctx)
	require.Equal(t, "bar", ccp.Name)
}

func TestCCP_DefaultsMultipleNone(t *testing.T) {
	ts := NewTestStore(t, "ccp")
	defer ts.Done(t)

	ts.AddCluster(t, "foo")
	ts.AddCluster(t, "bar")

	ctx, err := NewActx(nil, nil)
	require.NoError(t, err)

	ccp := ClusterContextParams{}
	ccp.SetDefaults(ctx)
	require.Equal(t, "", ccp.Name)
}

func TestCCP_DefaultsPath(t *testing.T) {
	ts := NewTestStore(t, "ccp")
	defer ts.Done(t)

	ts.AddCluster(t, "foo")
	ts.AddCluster(t, "bar")

	ctx, err := NewActx(nil, nil)
	require.NoError(t, err)

	ccp := ClusterContextParams{}
	ccp.SetDefaults(ctx)
	require.Equal(t, "", ccp.Name)
}

func TestCCP_Edit(t *testing.T) {
	ts := NewTestStore(t, "ccp")
	defer ts.Done(t)
	defer cli.ResetPromptLib()

	ts.AddCluster(t, "foo")
	ts.AddCluster(t, "bar")
	ts.AddCluster(t, "baz")

	cli.SetPromptLib(cli.NewTestPrompts([]interface{}{2}))
	ctx, err := NewActx(nil, nil)
	require.NoError(t, err)

	ccp := ClusterContextParams{}
	ccp.SetDefaults(ctx)
	require.Equal(t, "", ccp.Name)

	require.NoError(t, ccp.Edit(ctx))
	require.Contains(t, []string{"foo", "bar", "baz"}, ccp.Name)
}

func TestCCP_ValidateEmpty(t *testing.T) {
	ts := NewTestStore(t, "ccp")
	defer ts.Done(t)
	defer cli.ResetPromptLib()

	ctx, err := NewActx(&cobra.Command{}, nil)
	require.NoError(t, err)

	ccp := ClusterContextParams{}
	ccp.SetDefaults(ctx)
	require.Equal(t, "", ccp.Name)

	err = ccp.Validate(ctx)
	require.Error(t, err)
	require.Equal(t, "a cluster is required", err.Error())
}

func TestCCP_Validate(t *testing.T) {
	ts := NewTestStore(t, "ccp")
	defer ts.Done(t)

	ts.AddCluster(t, "foo")
	ctx, err := NewActx(nil, nil)
	require.NoError(t, err)

	ccp := ClusterContextParams{}
	ccp.SetDefaults(ctx)
	err = ccp.Validate(ctx)
	require.NoError(t, err)
	require.Equal(t, "foo", ccp.Name)
}
