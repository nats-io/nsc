// Copyright 2024-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_AddMappingCannotExceed100(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	// add a default mapping at a 100, default mapping at max
	_, err := ExecuteCmd(createAddMappingCmd(), []string{"--from", "q", "--to", "qq", "--weight", "100"}...)
	require.NoError(t, err)

	// default mapping cannot be incremented
	_, err = ExecuteCmd(createAddMappingCmd(), []string{"--from", "q", "--to", "qqq", "--weight", "10"}...)
	require.Error(t, err)
	require.ErrorContains(t, err, "Mapping \"q\" exceeds 100%")

	// the cli didn't add the extra mapping
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	mappings := ac.Mappings["q"]
	require.Len(t, mappings, 1)
	require.Equal(t, jwt.WeightedMapping{
		Subject: "qq",
		Cluster: "",
		Weight:  100,
	}, mappings[0])

	// can add another mapping but has to be for cluster
	_, err = ExecuteCmd(createAddMappingCmd(), []string{"--from", "q", "--to", "qa", "--weight", "100", "--cluster", "A"}...)
	require.NoError(t, err)
	// and for another cluster
	_, err = ExecuteCmd(createAddMappingCmd(), []string{"--from", "q", "--to", "qb", "--weight", "100", "--cluster", "B"}...)
	require.NoError(t, err)

	// incrementing one of the above maxed clusters fails
	_, err = ExecuteCmd(createAddMappingCmd(), []string{"--from", "q", "--to", "qaa", "--weight", "10", "--cluster", "A"}...)
	require.Error(t, err)
	require.ErrorContains(t, err, "Mapping \"q\" in cluster \"A\" exceeds 100%")
}

func Test_AddMappingCrud(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	// add a default mapping at a 100, default mapping at max
	_, err := ExecuteCmd(createAddMappingCmd(), []string{"--from", "q", "--to", "qq", "--weight", "100"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	m := ac.Mappings["q"]
	require.NotNil(t, m)
	require.Equal(t, jwt.WeightedMapping{
		Subject: "qq",
		Weight:  100,
		Cluster: "",
	}, m[0])

	ts.AddAccount(t, "B")
	// add a default mapping at a 100, default mapping at max
	_, err = ExecuteCmd(createAddMappingCmd(), []string{"--from", "qq", "--to", "rr", "--weight", "100", "--cluster", "B"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	m = ac.Mappings["qq"]
	require.NotNil(t, m)
	require.Equal(t, jwt.WeightedMapping{
		Subject: "rr",
		Weight:  100,
		Cluster: "B",
	}, m[0])

	_, err = ExecuteCmd(createDeleteMappingCmd(), []string{"--from", "qq", "--to", "rr", "--cluster", "B"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	m = ac.Mappings["qq"]
	require.Nil(t, m)

	_, err = ExecuteCmd(createAddMappingCmd(), []string{"--from", "qq", "--to", "rr", "--weight", "0", "--cluster", "B"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	m = ac.Mappings["qq"]
	require.NotNil(t, m)
	require.Equal(t, jwt.WeightedMapping{
		Subject: "rr",
		Weight:  0,
		Cluster: "B",
	}, m[0])

}
