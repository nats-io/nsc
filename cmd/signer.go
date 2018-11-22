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

	"github.com/nats-io/nkeys"
)

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

	p.signerKP, err = ctx.StoreCtx().ResolveKey(p.kind, KeyPathFlag)
	if err != nil {
		return err
	}
	if p.signerKP == nil {
		label := fmt.Sprintf("%s keypath", p.kind.String())
		err = EditKeyPath(p.kind, label, &KeyPathFlag)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *SignerParams) Resolve(ctx ActionCtx) error {
	if p.signerKP != nil {
		return nil
	}

	var err error
	p.signerKP, err = ctx.StoreCtx().ResolveKey(p.kind, KeyPathFlag)
	if err != nil {
		return err
	}
	return nil
}
