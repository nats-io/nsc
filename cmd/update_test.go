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
	"time"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/stretchr/testify/require"
)

func TestUpdate_RunDoesntUpdateOrCheck(t *testing.T) {
	d := MakeTempDir(t)
	_ = os.Setenv(NscHomeEnv, d)
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("1.0.0")
	conf.LastUpdate = time.Now().Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string) (*selfupdate.Release, bool, error) {
		checkCalled = true
		var r selfupdate.Release
		r.Version = semver.MustParse("1.0.0")
		return nil, false, nil
	}
	updateFn = func(current semver.Version, slug string) (*selfupdate.Release, error) {
		updateCalled = true
		var r selfupdate.Release
		r.Version = semver.MustParse("1.0.0")
		return nil, nil
	}
	defer func() {
		_ = os.Setenv(NscHomeEnv, "")
		updateCheckFn = nil
		updateFn = nil
	}()

	su, err := NewSelfUpdate()
	require.NoError(t, err)
	require.NotNil(t, su)
	require.False(t, su.shouldCheck())
	_, err = su.Run()
	require.NoError(t, err)
	require.False(t, checkCalled)
	require.False(t, updateCalled)
}

func TestUpdate_NeedsUpdate(t *testing.T) {
	d := MakeTempDir(t)
	_ = os.Setenv(NscHomeEnv, d)
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("1.0.0")
	conf.LastUpdate = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string) (*selfupdate.Release, bool, error) {
		checkCalled = true
		var r selfupdate.Release
		r.Version = semver.MustParse("1.0.1")
		return &r, true, nil
	}
	updateFn = func(current semver.Version, slug string) (*selfupdate.Release, error) {
		updateCalled = true
		var r selfupdate.Release
		r.Version = semver.MustParse("1.0.1")
		return nil, nil
	}
	defer func() {
		_ = os.Setenv(NscHomeEnv, "")
		updateCheckFn = nil
		updateFn = nil
	}()

	su, err := NewSelfUpdate()
	require.NoError(t, err)
	require.NotNil(t, su)
	require.True(t, su.shouldCheck())
	_, err = su.Run()
	require.NoError(t, err)
	require.True(t, checkCalled)
	require.False(t, updateCalled)
}

func TestUpdate_DoUpdate(t *testing.T) {
	d := MakeTempDir(t)
	_ = os.Setenv(NscHomeEnv, d)
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("1.0.0")
	conf.LastUpdate = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string) (*selfupdate.Release, bool, error) {
		checkCalled = true
		var r selfupdate.Release
		r.Version = semver.MustParse("1.0.1")
		return &r, true, nil
	}
	updateFn = func(current semver.Version, slug string) (*selfupdate.Release, error) {
		updateCalled = true
		var r selfupdate.Release
		r.Version = semver.MustParse("1.0.1")
		r.ReleaseNotes = "f33dfac3"
		return &r, nil
	}
	defer func() {
		_ = os.Setenv(NscHomeEnv, "")
		updateCheckFn = nil
		updateFn = nil
	}()

	_, stderr, err := ExecuteCmd(createUpdateCommand())
	require.NoError(t, err)
	require.True(t, checkCalled)
	require.True(t, updateCalled)
	require.Contains(t, stderr, "f33dfac3")
}
