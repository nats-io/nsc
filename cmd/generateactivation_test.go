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
	"testing"

	"github.com/nats-io/nsc/cmd/store"
)

func TestGenerateActivation(t *testing.T) {
	_, pub, _ := CreateAccount(t)

	os.Setenv(store.DataHomeEnv, MakeTempDir(t))
	os.Setenv(store.DataProfileEnv, "test")
	InitStore(t)

	defer func() {
		os.Setenv(store.DataHomeEnv, "")
		os.Setenv(store.DataProfileEnv, "")
	}()

	tests := CmdTests{
		{createGenerateActivationCmd(), []string{"generate", "activation"}, nil, []string{"required flag(s) \"name\" not set"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name"}, nil, []string{"flag needs an argument"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test"}, nil, []string{"--public or --public-key"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test", "--public-key", "pk", "--public"}, nil, []string{"is not a valid account public key"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test", "--public-key", "pk"}, nil, []string{"not a valid account public key"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test", "--public-key", pub, "--expiry", "1", "--service", "a"}, nil, []string{"couldn't parse expiry"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test", "--public-key", pub, "--expiry", "5d", "--service", "a"}, nil, nil, false},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test", "--public-key", pub, "--max-messages", "5x", "--service", "a"}, nil, []string{"couldn't parse number"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test", "--public-key", pub, "--max-messages", "5k", "--service", "a"}, nil, nil, false},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test", "--public-key", pub, "--max-payload", "100X", "--service", "a"}, nil, []string{"couldn't parse data size"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--name", "test", "--public-key", pub, "--max-payload", "100b", "--service", "a"}, nil, nil, false},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--public-key", pub, "--name", "test"}, nil, []string{"error specify one of"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--public-key", pub, "--name", "test", "--stream"}, nil, []string{"flag needs an argument"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--public-key", pub, "--name", "test", "--service"}, nil, []string{"flag needs an argument"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--public-key", pub, "--name", "test", "--stream", "bar"}, nil, nil, false},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--public-key", pub, "--name", "test", "--service", "foo"}, nil, nil, false},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--public-key", pub, "--name", "test", "--service", "foo", "--source-network"}, nil, []string{"flag needs an argument"}, true},
		{createGenerateActivationCmd(), []string{"generate", "activation", "--public-key", pub, "--name", "test", "--service", "foo", "--source-network", "127.0.0/1"}, nil, nil, false},
	}
	tests.Run(t, "root", "generate")

}
