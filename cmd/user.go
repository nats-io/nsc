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
	"bytes"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/xlab/tablewriter"
)

type User struct {
	Name      string         `json:"name,omitempty"`
	PublicKey string         `json:"publicKey,omitempty"`
	Tag       jwt.StringList `json:"tag,omitempty"`
	Pub       jwt.Permission `json:"pub,omitempty"`
	Sub       jwt.Permission `json:"sub,omitempty"`
	jwt.Limits
}

func NewUser(publicKey string) *User {
	u := User{}
	u.PublicKey = publicKey
	return &u
}

type Users []User

func (u *User) String() string {
	n := u.Name
	if n == "" {
		n = "(not specified)"
	}
	return fmt.Sprintf("%s\t%s\t%s", n, u.PublicKey, strings.Join(u.Tag, ","))
}

func (u *User) Matches(term string) bool {
	if strings.Contains(u.PublicKey, term) {
		return true
	}
	if strings.Contains(u.Name, term) {
		return true
	}
	if strings.Contains(strings.Join(u.Tag, ""), term) {
		return true
	}
	return false
}

func (u *User) Describe() []byte {
	buf := bytes.NewBuffer(nil)

	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle(fmt.Sprintf("User: %s", DefaultName(u.Name)))
	table.AddRow("Public Key:", u.PublicKey)
	if len(u.Pub.Allow) > 0 {
		table.AddRow("Publish Permissions:", strings.Join(u.Pub.Allow, ","))
	}
	if len(u.Pub.Deny) > 0 {
		table.AddRow("Deny Publish Permissions:", strings.Join(u.Pub.Deny, ","))
	}
	if len(u.Sub.Allow) > 0 {
		table.AddRow("Subscribe Permissions:", strings.Join(u.Sub.Allow, ","))
	}
	if len(u.Sub.Deny) > 0 {
		table.AddRow("Deny Subscribe Permissions:", strings.Join(u.Sub.Deny, ","))
	}

	if len(u.Tag) > 0 {
		table.AddRow("Tags:", strings.Join(u.Tag, ","))
	}

	if u.Max > 0 {
		table.AddRow("Max Messages:", u.Max)
	}

	if u.Payload > 0 {
		table.AddRow("Max Payload:", u.Payload)
	}

	if u.Src != "" {
		table.AddRow("Network Source:", u.Src)
	}

	buf.WriteString(table.Render())
	return buf.Bytes()
}

func PrintUsers(u *[]User) {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Users")
	table.AddHeaders("Name", "Key", "Tags")
	for _, e := range *u {
		table.AddRow(DefaultName(e.Name), e.PublicKey, strings.Join(e.Tag, ","))
	}
	fmt.Println(table.Render())
}

func (u *User) Store(overwrite bool) error {
	s, err := getStore()
	if err != nil {
		return fmt.Errorf("error loading store: %v", err)
	}

	if !LooksLikeNKey(u.PublicKey, 'U') {
		return fmt.Errorf("public key %q doesn't look like user nkey: %v", u.PublicKey, err)
	}

	kp, err := ParseNKey(u.PublicKey)
	if err != nil {
		return err
	}

	keyBytes, err := kp.PublicKey()
	if err != nil {
		return err
	}
	u.PublicKey = string(keyBytes)

	if !nkeys.IsValidPublicUserKey([]byte(u.PublicKey)) {
		return fmt.Errorf("not a valid public user key: %q", u.PublicKey)
	}

	_, err = nkeys.Decode(nkeys.PrefixByteUser, []byte(u.PublicKey))
	if err != nil {
		return fmt.Errorf("error decoding public key: %v", err)
	}

	ep := path.Join(store.Users, u.PublicKey+".user")
	if s.Has(ep) && !overwrite {
		return fmt.Errorf("error user identified by public key %q already exists", u.PublicKey)
	}

	if err := s.WriteEntry(ep, &u); err != nil {
		return fmt.Errorf("error writing user: %v", err)
	}

	return nil
}

func (u *User) Load() error {
	s, err := getStore()
	if err != nil {
		return fmt.Errorf("error loading store: %v", err)
	}

	_, err = nkeys.Decode(nkeys.PrefixByteUser, []byte(u.PublicKey))
	if err != nil {
		return fmt.Errorf("error decoding public key: %v", err)
	}

	ep := path.Join(store.Users, u.PublicKey+".user")
	if !s.Has(ep) {
		return fmt.Errorf("error user %q was not found", u.PublicKey)
	}

	return s.ReadEntry(ep, &u)
}

func (u *User) Delete() error {
	s, err := getStore()
	if err != nil {
		return fmt.Errorf("error loading store: %v", err)
	}

	ep := path.Join(store.Users, u.PublicKey+".user")
	return s.Delete(ep)
}

func ListUsers() ([]User, error) {
	s, err := getStore()
	if err != nil {
		return nil, fmt.Errorf("error loading store: %v\n", err)
	}

	a, err := s.List(store.Users, ".user")
	if err != nil {
		return nil, fmt.Errorf("error listing users: %v\n", err)
	}

	users := make([]User, 0)
	if len(a) == 0 {
		return users, nil
	}
	for _, n := range a {
		ep := filepath.Join(store.Users, n)
		u := User{}
		if err := s.ReadEntry(ep, &u); err != nil {
			return nil, fmt.Errorf("error reading entry %q: %v\n", ep, err)
		}
		users = append(users, u)
	}
	return users, nil
}

func PickUser() (*User, error) {
	users, err := ListUsers()
	if err != nil {
		return nil, err
	}
	var choices []string
	for _, u := range users {
		choices = append(choices, u.String())
	}
	idx, err := cli.PromptChoices("Select the user", choices)
	if err != nil {
		return nil, fmt.Errorf("error processing input: %v\n", err)
	}
	return &users[idx], nil
}

func PickUsers() ([]*User, error) {
	users, err := ListUsers()
	if err != nil {
		return nil, err
	}
	var choices []string
	for _, u := range users {
		choices = append(choices, u.String())
	}
	idxs, err := cli.PromptMultipleChoices("Select the user", choices)
	if err != nil {
		return nil, fmt.Errorf("error processing input: %v\n", err)
	}

	var v []*User
	for _, i := range idxs {
		v = append(v, &users[i])
	}

	return v, nil
}
