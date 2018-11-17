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
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
)

func PickAccount(ctx *store.Context, name string) (string, error) {
	if name == "" {
		name = ctx.Account.Name
	}

	if name == "" {
		accounts, err := ctx.Store.ListSubContainers(store.Accounts)
		if err != nil {
			return "", err
		}
		if len(accounts) > 1 {
			i, err := cli.PromptChoices("select account", accounts)
			if err != nil {
				return "", err
			}
			name = accounts[i]
		}
	}
	// allow downstream use of context to have account
	ctx.Account.Name = name

	return name, nil
}
