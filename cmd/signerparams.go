/*
 * Copyright 2018-2019 The NATS Authors
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
	"os"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
)

// SignerParams is shared UI for a signer (-K flag). The key
// for a signer is never generated and must be provided
type SignerParams struct {
	kind     nkeys.PrefixByte
	signerKP nkeys.KeyPair
}

func (p *SignerParams) SetDefaults(kind nkeys.PrefixByte, allowManaged bool, ctx ActionCtx) {
	p.kind = kind
	if allowManaged {
		if ctx.StoreCtx().Store.IsManaged() && p.kind == nkeys.PrefixByteOperator {
			p.kind = nkeys.PrefixByteAccount
		}
	}
}

func (p *SignerParams) Edit(ctx ActionCtx) error {
	var err error

	sctx := ctx.StoreCtx()
	p.signerKP, _ = sctx.ResolveKey(p.kind, KeyPathFlag)

	// skip showing a signer
	if p.signerKP != nil && ctx.StoreCtx().Store.IsManaged() {
		return nil
	}

	// build a list of the signing keys
	var signers []string
	if KeyPathFlag == "" {
		ks := sctx.KeyStore
		switch p.kind {
		case nkeys.PrefixByteOperator:
			KeyPathFlag = ks.GetKeyPath(sctx.Operator.PublicKey)
			signers, err = ctx.StoreCtx().GetOperatorKeys()
			if err != nil {
				return err
			}
		case nkeys.PrefixByteAccount:
			KeyPathFlag = ks.GetKeyPath(sctx.Account.PublicKey)
			signers, err = ctx.StoreCtx().GetAccountKeys(sctx.Account.Name)
			if err != nil {
				return err
			}
		}
	}

	// show an abbreviated path
	if KeyPathFlag != "" {
		KeyPathFlag = AbbrevHomePaths(KeyPathFlag)
	}
	// allow selecting a key from the ones we have
	var notFound []string
	var keys []string
	for _, s := range signers {
		fp := ctx.StoreCtx().KeyStore.GetKeyPath(s)
		_, err := os.Stat(fp)
		if err == nil {
			keys = append(keys, AbbrevHomePaths(fp))
		} else {
			notFound = append(notFound, ShortCodes(s))
		}
	}
	// maybe add an option for asking for one we don't have
	idx := -1
	if len(notFound) > 0 {
		idx = len(keys)
		keys = append(keys, "Other...")
	}

	// pick a key
	choice, err := cli.PromptChoices("select the key to use for signing", KeyPathFlag, keys)
	if err != nil {
		return err
	}
	// if it is the extra option, ask for a path/key
	if idx != -1 && choice == idx {
		label := fmt.Sprintf("path to signer %s nkey or nkey", p.kind.String())
		// key must be one from keys
		KeyPathFlag, err = cli.Prompt(label, KeyPathFlag, true, NKeyValidatorMatching(p.kind, signers))
		if err != nil {
			return err
		}
	} else {
		// they picked one
		KeyPathFlag = keys[choice]
	}

	// re-resolve the value using the user's input
	p.signerKP, err = sctx.ResolveKey(p.kind, KeyPathFlag)
	return err
}

func (p *SignerParams) Resolve(ctx ActionCtx) error {
	if p.signerKP != nil {
		return nil
	}

	var err error
	p.signerKP, err = ctx.StoreCtx().ResolveKey(p.kind, KeyPathFlag)

	if p.signerKP == nil && err == nil && KeyPathFlag != "" {
		// we have no resolution but arg was provided
		// this means that the file doesn't exist
		err = fmt.Errorf("%q - no such file or directory", AbbrevHomePaths(KeyPathFlag))
	}

	return err
}
