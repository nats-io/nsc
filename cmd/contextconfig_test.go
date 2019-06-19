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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextConfig_Empty(t *testing.T) {
	c, err := NewContextConfig("")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.True(t, (ContextConfig{}) == *c)
}

func TestContextConfig_BadDir(t *testing.T) {
	fp := filepath.Join(MakeTempDir(t), "foo")
	c, err := NewContextConfig(fp)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, fp, c.StoreRoot)
}

func TestContextConfig_LoadDefaultOperator(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, storesDir, c.StoreRoot)
	require.Equal(t, "operator", c.Operator)
}

func TestContextConfig_LoadMultipleOperator(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddOperator(t, "operator2")

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)

	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, storesDir, c.StoreRoot)
	require.Equal(t, "", c.Operator)
}

func TestContextConfig_SetValidOperator(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddOperator(t, "operator2")

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)
	err = c.SetOperator("operator2")
	require.NoError(t, err)
	require.Equal(t, "operator2", c.Operator)
}

func TestContextConfig_SetInvalidOperator(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)
	err = c.SetOperator("bar")
	require.Error(t, err)
}

func TestContextConfig_SetEptyOperator(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)
	err = c.SetOperator("")
	require.NoError(t, err)
}

func TestContextConfig_Account(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, storesDir, c.StoreRoot)
	require.Equal(t, "operator", c.Operator)
	require.Equal(t, "A", c.Account)
}

func TestContextConfig_LoadMultipleAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Equal(t, storesDir, c.StoreRoot)
	require.Equal(t, "operator", c.Operator)
	require.Equal(t, "", c.Account)
}

func TestContextConfig_SetValidAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)

	ts.AddAccount(t, "B")
	err = c.SetAccount("B")
	require.NoError(t, err)
	require.Equal(t, "B", c.Account)
}

func TestContextConfig_SetInvalidAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)

	err = c.SetAccount("B")
	require.Error(t, err)
}

func TestContextConfig_SetEmptyAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)

	err = c.SetAccount("")
	require.NoError(t, err)
}

func TestContextConfig_ListOperators(t *testing.T) {
	ts := NewTestStore(t, "op")
	defer ts.Done(t)

	ts.AddOperator(t, "op2")

	storesDir := filepath.Dir(ts.Store.Dir)
	c, err := NewContextConfig(storesDir)
	require.NoError(t, err)
	require.NotNil(t, c)

	ops := c.ListOperators()
	require.NotNil(t, ops)

	require.ElementsMatch(t, ops, []string{"op", "op2"})
}
