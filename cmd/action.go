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
	"strings"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

type ActionCtx interface {
	StoreCtx() *store.Context
	CurrentCmd() *cobra.Command
	Args() []string
	NothingToDo(flagNames ...string) bool
	AllSet(flagNames ...string) bool
	AnySet(flagNames ...string) bool
	CountSet(flagNames ...string) int
}

type ActionFn func(ctx ActionCtx) error
type ActionRunFn func(ctx ActionCtx) (store.Status, error)

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
	Run(ctx ActionCtx) (store.Status, error)
}

type Actx struct {
	ctx  *store.Context
	cmd  *cobra.Command
	args []string
}

func NewActx(cmd *cobra.Command, args []string) (ActionCtx, error) {
	s, err := GetStore()
	// in the case of add operator, there might not be a store
	if err == ErrNoOperator {
		if cmd.Name() == "operator" && cmd.Parent().Name() == "add" {
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return nil, err
	}

	return &Actx{cmd: cmd, ctx: ctx, args: args}, nil
}

func NewStoreLessActx(cmd *cobra.Command, args []string) (ActionCtx, error) {
	var ctx Actx
	ctx.cmd = cmd
	ctx.args = args
	ctx.ctx = &store.Context{}
	return &ctx, nil
}

func RunMaybeStorelessAction(cmd *cobra.Command, args []string, action interface{}) error {
	ctx, err := NewActx(cmd, args)
	if err != nil {
		ctx, err = NewStoreLessActx(cmd, args)
		if err != nil {
			return err
		}
	}
	return run(ctx, action)

}

func RunStoreLessAction(cmd *cobra.Command, args []string, action interface{}) error {
	ctx, err := NewStoreLessActx(cmd, args)
	if err != nil {
		return err
	}
	return run(ctx, action)
}

func RunAction(cmd *cobra.Command, args []string, action interface{}) error {
	ctx, err := NewActx(cmd, args)
	if err != nil {
		return err
	}
	return run(ctx, action)
}

func run(ctx ActionCtx, action interface{}) error {
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

	rs, err := e.Run(ctx)
	if rs != nil {
		ctx.CurrentCmd().Println(rs.Message())
		sum, ok := rs.(store.Summarizer)
		if ok {
			m, err := sum.Summary()
			if err != nil {
				return err
			}
			if m != "" {
				if strings.HasSuffix(m, "\n") {
					m = m[:len(m)-1]
				}
				ctx.CurrentCmd().Println(m)
			}
		}
	}
	return err
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

// AnySet returns true if any of the flags are set
func (c *Actx) AnySet(flagNames ...string) bool {
	for _, n := range flagNames {
		if c.cmd.Flag(n).Changed {
			return true
		}
	}
	return false
}

// AllSet returns true if all flags are set
func (c *Actx) AllSet(flagNames ...string) bool {
	count := 0
	for _, n := range flagNames {
		if c.cmd.Flag(n).Changed {
			count++
		}
	}
	return len(flagNames) == count
}

func (c *Actx) CountSet(flagNames ...string) int {
	count := 0
	for _, n := range flagNames {
		if c.cmd.Flag(n).Changed {
			count++
		}
	}
	return count
}
