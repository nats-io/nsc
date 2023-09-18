/*
 * Copyright 2018-2023 The NATS Authors
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

package store

import "github.com/nats-io/jwt/v2"

type IStore interface {
	IsManaged() bool
	Resolve(name ...string) string
	Has(name ...string) bool
	HasAccount(name string) bool
	Read(name ...string) ([]byte, error)
	Write(data []byte, name ...string) error
	Delete(name ...string) error
	ListSubContainers(name ...string) ([]string, error)
	ListEntries(name ...string) ([]string, error)
	StoreClaim(data []byte) (*Report, error)
	StoreRaw(data []byte) error
	GetName() string
	LoadClaim(name ...string) (*jwt.GenericClaims, error)
	ReadOperatorClaim() (*jwt.OperatorClaims, error)
	ReadRawOperatorClaim() ([]byte, error)
	ReadAccountClaim(name string) (*jwt.AccountClaims, error)
	ReadRawAccountClaim(name string) ([]byte, error)
	ReadUserClaim(accountName string, name string) (*jwt.UserClaims, error)
	ReadRawUserClaim(accountName string, name string) ([]byte, error)
}
