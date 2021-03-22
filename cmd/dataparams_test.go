/*
 * Copyright 2018-2021 The NATS Authors
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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDataParams(t *testing.T) {
	var dp DataParams
	dp.Value = "1"
	v, err := dp.NumberValue()
	require.NoError(t, err)
	require.Equal(t, int64(1), v)

	dp.Value = "1B"
	v, err = dp.NumberValue()
	require.NoError(t, err)
	require.Equal(t, int64(1), v)

	dp.Value = "1K"
	v, err = dp.NumberValue()
	require.NoError(t, err)
	require.Equal(t, int64(1000), v)

	dp.Value = "1KiB"
	v, err = dp.NumberValue()
	require.NoError(t, err)
	require.Equal(t, int64(1024), v)

	dp.Value = "1M"
	v, err = dp.NumberValue()
	require.NoError(t, err)
	require.Equal(t, int64(1000*1000), v)

	dp.Value = "1MiB"
	v, err = dp.NumberValue()
	require.NoError(t, err)
	require.Equal(t, int64(1024*1024), v)

	dp.Value = "1G"
	v, err = dp.NumberValue()
	require.NoError(t, err)
	require.Equal(t, int64(1000*1000*1000), v)

	dp.Value = "1Gib"
	v, err = dp.NumberValue()
	require.NoError(t, err)
	require.Equal(t, int64(1024*1024*1024), v)
}
