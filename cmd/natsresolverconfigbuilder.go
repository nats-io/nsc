/*
 * Copyright 2018-2020 The NATS Authors
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
	"errors"
	"fmt"

	"github.com/nats-io/jwt"
)

type NatsResolverConfigBuilder struct {
	operator       string
	operatorName   string
	sysAccountSubj string
	sysAccount     string
	sysAccountName string
}

func NewNatsResolverConfigBuilder() *NatsResolverConfigBuilder {
	cb := NatsResolverConfigBuilder{}
	return &cb
}

func (cb *NatsResolverConfigBuilder) Add(rawClaim []byte) error {
	token := string(rawClaim)
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return err
	}
	switch gc.Type {
	case jwt.OperatorClaim:
		if claim, err := jwt.DecodeOperatorClaims(token); err != nil {
			return err
		} else {
			cb.operator = token
			cb.operatorName = claim.Name
		}
	case jwt.AccountClaim:
		if claim, err := jwt.DecodeAccountClaims(token); err != nil {
			return err
		} else if claim.Subject == cb.sysAccountSubj {
			cb.sysAccount = token
			cb.sysAccountName = claim.Name
		}
	}
	return nil
}

func (cb *NatsResolverConfigBuilder) SetOutputDir(fp string) error {
	return errors.New("nats-resolver configurations don't support directory output")
}

func (cb *NatsResolverConfigBuilder) SetSystemAccount(id string) error {
	cb.sysAccountSubj = id
	return nil
}

const tmpl = `# Operator named %s
operator: %s
# System Account named %s
system_account: %s

# configuration of the nats based resolver
resolver {
    type: full
    # Directory in which the account jwt will be stored
    dir: './jwt'
    # In order to support jwt deletion, set to true
    # If the resolver type is full delete will rename the jwt.
    # This is to allow manual restoration in case of inadvertent deletion.
    # To restore a jwt, remove the added suffix .delete and restart or send a reload signal.
    # To free up storage you must manually delete files with the suffix .delete.
    allow_delete: false
    # Interval at which a nats-server with a nats based account resolver will compare
    # it's state with one random nats based account resolver in the cluster and if needed, 
    # exchange jwt and converge on the same set of jwt.
    interval: "2m"
}

# Preload the nats based resolver with the system account jwt.
# This is not necessary but avoids a bootstrapping system account. 
# This only applies to the system account. Therefore other account jwt are not included here.
# To populate the resolver:
# 1) make sure that your operator has the account server URL pointing at your nats servers.
#    The url must start with: "nats://" 
#    nsc edit operator --account-jwt-server-url nats://localhost:4222
# 2) push your accounts using: nsc push --all
#    The argument to push -u is optional if your account server url is set as described.
# 3) to prune accounts use: nsc push --prune 
#    In order to enable prune you must set above allow_delete to true
# Later changes to the system account take precedence over the system account jwt listed here.
resolver_preload: {
	%s: %s,
}
`

func (cb *NatsResolverConfigBuilder) Generate() ([]byte, error) {
	if cb.operator == "" {
		return nil, errors.New("operator is not set")
	}
	if cb.sysAccountSubj == "" || cb.sysAccount == "" {
		return nil, errors.New("system account is not set")
	}
	return []byte(fmt.Sprintf(tmpl, cb.operatorName, cb.operator, cb.sysAccountName,
		cb.sysAccountSubj, cb.sysAccountSubj, cb.sysAccount)), nil
}
