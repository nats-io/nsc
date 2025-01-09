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
	"testing"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func Test_NewActRequiresAction(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	err := RunAction(nil, []string{"foo", "bar"}, "hello")
	require.Error(t, err)
	require.Equal(t, "action provided is not an Action", err.Error())
}

func TestActionContextSet(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ar := newDefaultAction()
	ar.setDefaults = func(ctx ActionCtx) error {
		require.NotNil(t, ctx)
		require.NotNil(t, ctx.StoreCtx())
		require.NotNil(t, ctx.CurrentCmd())
		require.Len(t, ctx.Args(), 2)
		require.Equal(t, "hello", ctx.Args()[0])
		require.Equal(t, "world", ctx.Args()[1])
		return nil
	}

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add assets such as accounts, imports, users, clusters, servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &ar); err != nil {
				return err
			}
			return nil
		},
	}

	_, err := ExecuteCmd(cmd, "hello", "world")
	require.NoError(t, err)
}

func TestActionInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	count := 0

	ar := newDefaultAction()
	ar.preInteractive = func(ctx ActionCtx) error {
		count++
		return nil
	}
	ar.postInteractive = func(ctx ActionCtx) error {
		count++
		return nil
	}

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add assets such as accounts, imports, users, clusters, servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &ar); err != nil {
				return err
			}
			return nil
		},
	}
	_, err := ExecuteInteractiveCmd(cmd, []interface{}{})
	require.NoError(t, err)
	require.Equal(t, 2, count)
}

func TestActionNothingToDoEmpty(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	var v string

	nothingToDo := false

	ar := newDefaultAction()
	ar.setDefaults = func(ctx ActionCtx) error {
		nothingToDo = ctx.NothingToDo("name")
		return nil
	}
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add assets such as accounts, imports, users, clusters, servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &ar); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&v, "name", "n", "", "account name")
	_, err := ExecuteCmd(cmd)
	require.NoError(t, err)
	require.True(t, nothingToDo)
}

func TestActionNothingToDoSet(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	var v string

	nothingToDo := false

	ar := newDefaultAction()
	ar.setDefaults = func(ctx ActionCtx) error {
		nothingToDo = ctx.NothingToDo("name")
		return nil
	}
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add assets such as accounts, imports, users, clusters, servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &ar); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&v, "name", "n", "", "account name")
	_, err := ExecuteCmd(cmd, "--name", "a")
	require.NoError(t, err)
	require.False(t, nothingToDo)
}

type actionResponse struct {
	setDefaults     ActionFn
	preInteractive  ActionFn
	load            ActionFn
	postInteractive ActionFn
	validate        ActionFn
	run             ActionRunFn
}

var nilResponse = func(ctx ActionCtx) error {
	return nil
}

var nilRunResponse = func(ctx ActionCtx) (store.Status, error) {
	return nil, nil
}

func (a *actionResponse) SetDefaults(ctx ActionCtx) error {
	return a.setDefaults(ctx)
}

func (a *actionResponse) PreInteractive(ctx ActionCtx) error {
	return a.preInteractive(ctx)
}

func (a *actionResponse) Load(ctx ActionCtx) error {
	return a.load(ctx)
}

func (a *actionResponse) PostInteractive(ctx ActionCtx) error {
	return a.postInteractive(ctx)
}

func (a *actionResponse) Validate(ctx ActionCtx) error {
	return a.validate(ctx)
}

func (a *actionResponse) Run(ctx ActionCtx) (store.Status, error) {
	return a.run(ctx)
}

func newDefaultAction() actionResponse {
	var ar actionResponse
	ar.setDefaults = nilResponse
	ar.preInteractive = nilResponse
	ar.load = nilResponse
	ar.postInteractive = nilResponse
	ar.validate = nilResponse
	ar.run = nilRunResponse

	return ar
}

func TestActionMessage(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ar := newDefaultAction()
	ar.run = func(ctx ActionCtx) (store.Status, error) {
		return store.OKStatus("this is a test message"), nil
	}

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add assets such as accounts, imports, users, clusters, servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &ar); err != nil {
				return err
			}
			return nil
		},
	}

	out, err := ExecuteCmd(cmd)
	require.NoError(t, err)
	require.Contains(t, out.Out, "this is a test message")
}
