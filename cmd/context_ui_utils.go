package cmd

import (
	"fmt"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
)

func PickAccount(ctx *store.Context, name string) (string, error) {
	if name == "" {
		name = ctx.Account.Name
	}

	accounts, err := ctx.Store.ListSubContainers(store.Accounts)
	if err != nil {
		return "", err
	}
	if len(accounts) == 0 {
		return "", fmt.Errorf("no accounts defined - add one first")
	}
	if len(accounts) == 1 {
		name = accounts[0]
	}
	if len(accounts) > 1 {
		i, err := cli.Select("select account", name, accounts)
		if err != nil {
			return "", err
		}
		name = accounts[i]
	}

	// allow downstream use of context to have account
	ctx.Account.Name = name

	return name, nil
}

func PickUser(ctx *store.Context, accountName string) (string, error) {
	var err error
	if accountName == "" {
		accountName = ctx.Account.Name
	}

	if accountName == "" {
		accountName, err = PickAccount(ctx, accountName)
		if err != nil {
			return "", err
		}
	}
	// allow downstream use of context to have account
	ctx.Account.Name = accountName

	users, err := ctx.Store.ListEntries(store.Accounts, accountName, store.Users)
	if err != nil {
		return "", err
	}
	if len(users) == 0 {
		return "", fmt.Errorf("account %q doesn't have any users - add one first", accountName)
	}
	if len(users) == 1 {
		return users[0], nil
	}
	if len(users) > 1 {
		i, err := cli.Select("select user", "", users)
		if err != nil {
			return "", err
		}
		return users[i], nil
	}
	return "", nil
}
