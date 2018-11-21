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
	"fmt"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

////this is shared by all cmds that may require an account as an argument
//var AccountFlag string
//
//// this is shared by all cmds that may require an cluster as an argument
//var ClusterFlag string
//
//func HoistAccountFlag(cmd *cobra.Command) {
//	cmd.Flags().StringVarP(&AccountFlag, "account", "a", "", "account name")
//}
//
//func HoistClusterFlag(cmd *cobra.Command) {
//	cmd.Flags().StringVarP(&AccountFlag, "cluster", "c", "", "cluster name")
//}

type ActionCtx interface {
	StoreCtx() *store.Context
	CurrentCmd() *cobra.Command
	Args() []string
	NothingToDo(flagNames ...string) bool
}

type ActionFn func(ctx ActionCtx) error

type Action interface {
	// SetDefaults that can be derived from cmd flags
	SetDefaults(ctx ActionCtx) error
	// PreInteractive ask user for values
	PreInteractive(ctx ActionCtx) error
	// Load any data needed for the Run
	Load(ctx ActionCtx) error
	// PostInteractive ask user for values related to the action
	PostInteractive(ctx ActionCtx) error
	// Validate the action
	Validate(ctx ActionCtx) error
	// Run the action
	Run(ctx ActionCtx) error
}

type Actx struct {
	ctx  *store.Context
	cmd  *cobra.Command
	args []string
}

func NewActx(cmd *cobra.Command, args []string) (ActionCtx, error) {
	s, err := GetStore()
	if err != nil {
		return nil, err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return nil, err
	}

	//if AccountFlag != "" {
	//	ctx.Account.Name = AccountFlag
	//}
	//if AccountFlag == "" {
	//	AccountFlag = ctx.Account.Name
	//}
	//if ClusterFlag != "" {
	//	ctx.Cluster.Name = ClusterFlag
	//}
	//if ClusterFlag == "" {
	//	ClusterFlag = ctx.Cluster.Name
	//}

	return &Actx{cmd: cmd, ctx: ctx, args: args}, nil
}

func RunAction(cmd *cobra.Command, args []string, action interface{}) error {
	ctx, err := NewActx(cmd, args)
	if err != nil {
		return err
	}

	e, ok := action.(Action)
	if !ok {
		return fmt.Errorf("action provided is not an Action")
	}
	if err := e.SetDefaults(ctx); err != nil {
		return err
	}

	if InteractiveFlag {
		if err := e.PreInteractive(ctx); err != nil {
			return err
		}
	}

	if err := e.Load(ctx); err != nil {
		return err
	}

	if InteractiveFlag {
		if err := e.PostInteractive(ctx); err != nil {
			return err
		}
	}

	if err := e.Validate(ctx); err != nil {
		return err
	}

	if err := e.Run(ctx); err != nil {
		return err
	}

	return RunInterceptor(ctx)

}

func (c *Actx) StoreCtx() *store.Context {
	return c.ctx
}

func (c *Actx) CurrentCmd() *cobra.Command {
	return c.cmd
}

func (c *Actx) Args() []string {
	return c.args
}

func (c *Actx) NothingToDo(flagNames ...string) bool {
	for _, n := range flagNames {
		if c.cmd.Flag(n).Changed {
			return false
		}
	}
	return true
}
