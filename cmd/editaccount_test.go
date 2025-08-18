// Copyright 2018-2025 The NATS Authors
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
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func Test_EditAccount(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	tests := CmdTests{
		{createEditAccount(), []string{"edit", "account"}, nil, []string{"specify an edit option"}, true},
		{createEditAccount(), []string{"edit", "account", "--info-url", "http://foo/bar"}, []string{"changed info url to"}, nil, false},
		{createEditAccount(), []string{"edit", "account", "--description", "my account is about this"}, []string{"changed description to"}, nil, false},
		{createEditAccount(), []string{"edit", "account", "--tag", "A", "--name", "A"}, []string{"edited account \"A\""}, nil, false},
	}

	tests.Run(t, "root", "edit")
}

func Test_EditAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	require.NoError(t, GetConfig().SetAccount(""))
	_, err := ExecuteCmd(createEditAccount(), []string{"--tag", "A"}...)
	require.Error(t, err)
	require.Contains(t, "an account is required", err.Error())
}

func Test_EditAccount_Tag(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditAccount(), []string{"--tag", "A,B,C"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	require.Len(t, ac.Tags, 3)
	require.ElementsMatch(t, ac.Tags, []string{"a", "b", "c"})
}

func Test_EditAccount_RmTag(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditAccount(), []string{"--tag", "A,B,C"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createEditAccount(), []string{"--rm-tag", "A,B"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	require.Len(t, ac.Tags, 1)
	require.ElementsMatch(t, ac.Tags, []string{"c"})
}

func Test_EditAccount_Times(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(createEditAccount(), []string{"--start", "2018-01-01", "--expiry", "2050-01-01"}...)
	require.NoError(t, err)

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)

	expiry, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, start, ac.NotBefore)
	require.Equal(t, expiry, ac.Expires)
}

func Test_EditAccountLimits(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditAccount(), []string{"--conns", "5", "--data", "10mib", "--exports", "15",
		"--imports", "20", "--payload", "1Kib", "--subscriptions", "30", "--leaf-conns", "31",
		"--js-streams", "5", "--js-consumer", "6", "--js-disk-storage", "7", "--js-mem-storage", "8",
		"--js-max-disk-stream", "9mib", "--js-max-mem-stream", "10", "--js-max-ack-pending", "11", "--js-max-bytes-required"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, int64(5), ac.Limits.Conn)
	require.Equal(t, int64(31), ac.Limits.LeafNodeConn)
	require.Equal(t, int64(1024*1024*10), ac.Limits.Data)
	require.Equal(t, int64(15), ac.Limits.Exports)
	require.Equal(t, int64(20), ac.Limits.Imports)
	require.Equal(t, int64(1024), ac.Limits.Payload)
	require.Equal(t, int64(30), ac.Limits.Subs)
	require.Equal(t, int64(5), ac.Limits.Streams)
	require.Equal(t, int64(6), ac.Limits.Consumer)
	require.Equal(t, int64(7), ac.Limits.DiskStorage)
	require.Equal(t, int64(8), ac.Limits.MemoryStorage)
	require.Equal(t, int64(1024*1024*9), ac.Limits.DiskMaxStreamBytes)
	require.Equal(t, int64(10), ac.Limits.MemoryMaxStreamBytes)
	require.Equal(t, int64(11), ac.Limits.MaxAckPending)
	require.True(t, ac.Limits.MaxBytesRequired)
}

func Test_EditJsOptionsOnTierDelete(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditAccount(), []string{"--js-streams", "5", "--js-consumer", "6", "--js-disk-storage", "7"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, int64(5), ac.Limits.Streams)
	require.Equal(t, int64(6), ac.Limits.Consumer)
	require.Equal(t, int64(7), ac.Limits.DiskStorage)

	_, err = ExecuteCmd(createEditAccount(), []string{"--js-streams", "1", "--rm-js-tier", "0"}...)
	require.Error(t, err)
	require.Equal(t, "rm-js-tier is exclusive of all other js options", err.Error())

	_, err = ExecuteCmd(createEditAccount(), []string{"--rm-js-tier", "0"}...)
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, int64(0), ac.Limits.Streams)
	require.Equal(t, int64(0), ac.Limits.Consumer)
	require.Equal(t, int64(0), ac.Limits.DiskStorage)
}

func Test_GlobalPreventsTiered(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditAccount(), []string{"--js-streams", "5", "--js-disk-storage", "10"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, int64(5), ac.Limits.Streams)

	_, err = ExecuteCmd(createEditAccount(), []string{"--js-tier", "1", "--js-disk-storage", "10"}...)
	require.Error(t, err)
	require.Equal(t, "cannot set a jetstream tier limit when a configuration has a global limit", err.Error())
}

func Test_TieredPreventsGlobal(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditAccount(), []string{"--js-tier", "2", "--js-streams", "5", "--js-disk-storage", "10"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, int64(5), ac.Limits.JetStreamTieredLimits["R2"].Streams)

	_, err = ExecuteCmd(createEditAccount(), []string{"--js-disk-storage", "10"}...)
	require.Error(t, err)
	require.Equal(t, "cannot set a jetstream global limit when a configuration has tiered limits 'R2'", err.Error())
}

func Test_TieredDoesntPreventOtherClaims(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditAccount(), []string{"--js-tier", "2", "--js-streams", "5", "--js-disk-storage", "10"}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, int64(5), ac.Limits.JetStreamTieredLimits["R2"].Streams)

	_, err = ExecuteCmd(createEditAccount(), []string{"--sk", "generate"}...)
	require.NoError(t, err)
}

func Test_EditAccountSigningKeys(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, pk, _ := CreateAccountKey(t)
	_, pk2, _ := CreateAccountKey(t)

	_, err := ExecuteCmd(createEditAccount(), []string{"--sk", pk, "--sk", pk2}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, pk)
	require.Contains(t, ac.SigningKeys, pk2)

	_, err = ExecuteCmd(createEditAccount(), []string{"--rm-sk", pk}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotContains(t, ac.SigningKeys, pk)
}

func Test_EditAccount_Pubs(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(createEditAccount(), []string{"--allow-pub", "a,b", "--allow-pubsub", "c", "--deny-pub", "foo", "--deny-pubsub", "bar"}...)
	require.NoError(t, err)

	cc, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Allow, []string{"a", "b", "c"})
	require.ElementsMatch(t, cc.DefaultPermissions.Sub.Allow, []string{"c"})
	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Deny, []string{"foo", "bar"})
	require.ElementsMatch(t, cc.DefaultPermissions.Sub.Deny, []string{"bar"})

	_, err = ExecuteCmd(createEditAccount(), []string{"--rm", "c,bar"}...)
	require.NoError(t, err)
	cc, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Allow, []string{"a", "b"})
	require.Len(t, cc.DefaultPermissions.Sub.Allow, 0)
	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Deny, []string{"foo"})
	require.Len(t, cc.DefaultPermissions.Sub.Deny, 0)
}

func Test_EditAccountResponsePermissions(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(createEditAccount(), []string{"--max-responses", "1000", "--response-ttl", "4ms"}...)
	require.NoError(t, err)

	uc, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, uc.DefaultPermissions.Resp)
	require.Equal(t, 1000, uc.DefaultPermissions.Resp.MaxMsgs)
	d, _ := time.ParseDuration("4ms")
	require.Equal(t, d, uc.DefaultPermissions.Resp.Expires)

	_, err = ExecuteCmd(createEditAccount(), []string{"--rm-response-perms"}...)
	require.NoError(t, err)

	uc, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Nil(t, uc.DefaultPermissions.Resp)
}

func Test_EditAccountSk(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	sk, err := nkeys.CreateOperator()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(sk)
	require.NoError(t, err)
	pSk, err := sk.PublicKey()
	require.NoError(t, err)

	_, err = ExecuteCmd(createEditOperatorCmd(), []string{"--sk", pSk}...)
	require.NoError(t, err)

	ts.AddAccountWithSigner(t, "A", sk)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Issuer, pSk)

	_, err = ExecuteCmd(createEditAccount(), []string{"--tag", "foo"}...)
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Issuer, pSk)
}

func Test_EditOperatorDisallowBearerToken(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	_, err := ExecuteCmd(createEditUserCmd(), []string{"--name", "U", "--bearer"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createEditAccount(), []string{"--name", "A", "--disallow-bearer"}...)
	require.Error(t, err)
	require.Equal(t, err.Error(), `user "U" in account "A" uses bearer token (needs to be deleted/changed first)`)

	// delete offending user
	_, err = ExecuteCmd(createDeleteUserCmd(), []string{"--account", "A", "--name", "U"}...)
	require.NoError(t, err)
	// set option
	_, err = ExecuteCmd(createEditAccount(), []string{"--name", "A", "--disallow-bearer"}...)
	require.NoError(t, err)
	// test user creation
	_, err = ExecuteCmd(CreateAddUserCmd(), []string{"--account", "A", "--name", "U", "--bearer"}...)
	require.Error(t, err)
	require.Equal(t, err.Error(), `account "A" forbids the use of bearer token`)
	_, err = ExecuteCmd(CreateAddUserCmd(), []string{"--account", "A", "--name", "U"}...)
	require.NoError(t, err)
	_, err = ExecuteCmd(createEditUserCmd(), []string{"--account", "A", "--name", "U", "--bearer"}...)
	require.Error(t, err)
	require.Equal(t, err.Error(), "account disallows bearer token")
}

func Test_EditSysAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "SYS")
	_, err := ExecuteCmd(createEditOperatorCmd(), []string{"--system-account", "SYS"}...)
	require.NoError(t, err)

	// test setting any flag will generate an error and the flag is reported
	jsOptions := []string{
		"js-max-bytes-required",
		"js-tier",
		"js-mem-storage",
		"js-disk-storage",
		"js-streams",
		"js-consumer",
		"js-max-mem-stream",
		"js-max-disk-stream",
		"js-max-ack-pending",
	}
	// setting any JS flags, will fail the edit
	for idx, n := range jsOptions {
		flag := fmt.Sprintf("--%s", n)
		if idx > 0 {
			_, err = ExecuteCmd(createEditAccount(), []string{"SYS", "--tag", "A", flag, "1"}...)
			require.Error(t, err)
			require.Contains(t, err.Error(), flag)
		} else {
			_, err = ExecuteCmd(createEditAccount(), []string{"SYS", "--tag", "A", flag}...)
			require.Error(t, err)
			require.Contains(t, err.Error(), flag)
		}
	}
	// defaults are removed automatically
	_, err = ExecuteCmd(createEditAccount(), []string{"SYS", "--tag", "A"}...)
	require.NoError(t, err)
}

func Test_TierRmAndDisabled(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(createEditAccount(), []string{"A", "--rm-js-tier", "1", "--js-disable"}...)
	require.Error(t, err)
	require.Equal(t, err.Error(), "js-disable is exclusive of all other js options")
}

func Test_TracingSampling(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	// cannot set sampling if no subject
	_, err := ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-sampling", "50"}...)
	require.Error(t, err)
	require.Equal(t, "trace-context-sampling requires a subject", err.Error())

	// set a subject
	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-subject", "traces"}...)
	require.NoError(t, err)

	// range checks
	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-sampling", "101"}...)
	require.Error(t, err)
	require.Equal(t, "tracing sampling rate must be between 1-100", err.Error())

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-sampling", "-1"}...)
	require.Error(t, err)
	require.Equal(t, "tracing sampling rate must be between 1-100", err.Error())

	// disable and set
	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-sampling", "50", "--trace-context-subject", ""}...)
	require.Error(t, err)
	require.Equal(t, "cannot set context sampling rate when disabling the trace context", err.Error())
}

func Test_TracingSubject(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Nil(t, ac.Trace)

	// no op
	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-subject", ""}...)
	require.NoError(t, err)

	// bad subjects are checked by jwt lib, just making sure we are catching
	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-subject", "traces.*"}...)
	require.Error(t, err)
	require.Equal(t, "tracing subjects cannot contain wildcards: \"traces.*\"", err.Error())

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-subject", "traces.here"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac.Trace)
	require.Equal(t, jwt.Subject("traces.here"), ac.Trace.Destination)
	require.Equal(t, 0, ac.Trace.Sampling)

	// we have a subject, so set the sampling
	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-sampling", "75"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac.Trace)
	require.Equal(t, jwt.Subject("traces.here"), ac.Trace.Destination)
	require.Equal(t, 75, ac.Trace.Sampling)

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--trace-context-subject", ""}...)
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Nil(t, ac.Trace)
}

func Test_EnableTier(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Limits.JetStreamLimits, jwt.JetStreamLimits{})

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--js-enable", "0"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Limits.JetStreamLimits, jwt.JetStreamLimits{DiskStorage: -1, MemoryStorage: -1})
}

func Test_EnableTierDoesntClobber(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Limits.JetStreamLimits, jwt.JetStreamLimits{})

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--js-enable", "0"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--js-enable", "0"}...)
	require.Error(t, err)
	require.Equal(t, "jetstream tier global is already enabled", err.Error())
}

func Test_EnableTierNoOtherFlag(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Limits.JetStreamLimits, jwt.JetStreamLimits{})

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--js-enable", "0", "--rm-js-tier", "0"}...)
	require.Error(t, err)
	require.Equal(t, "rm-js-tier is exclusive of all other js options", err.Error())
}

func Test_CannotEnableJsInSys(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "SYS")
	_, err := ExecuteCmd(createEditOperatorCmd(), []string{"--system-account", "SYS"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createEditAccount(), []string{"--js-enable", "1"}...)
	require.Error(t, err)

	_, err = ExecuteCmd(createEditAccount(), []string{"--js-disable"}...)
	require.NoError(t, err)

	sys, err := ts.Store.ReadAccountClaim("SYS")
	require.NoError(t, err)

	require.False(t, sys.Limits.IsJSEnabled())
}

func Test_AllowSysToDisableJs(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "SYS")
	_, err := ExecuteCmd(createEditOperatorCmd(), []string{"--system-account", "SYS"}...)
	require.NoError(t, err)

	sys, err := ts.Store.ReadAccountClaim("SYS")
	require.NoError(t, err)
	require.False(t, sys.Limits.IsJSEnabled())

	sys.Limits.JetStreamTieredLimits = make(map[string]jwt.JetStreamLimits)
	sys.Limits.JetStreamTieredLimits["R1"] = jwt.JetStreamLimits{DiskStorage: -1, MemoryStorage: -1}

	okp, err := ts.KeyStore.GetKeyPair(ts.GetOperatorPublicKey(t))
	require.NoError(t, err)
	token, err := sys.Encode(okp)
	require.NoError(t, err)
	require.NoError(t, ts.Store.StoreRaw([]byte(token)))

	sys, err = ts.Store.ReadAccountClaim("SYS")
	require.NoError(t, err)
	require.True(t, sys.Limits.IsJSEnabled())

	_, err = ExecuteCmd(createEditAccount(), []string{"--js-disable"}...)
	require.NoError(t, err)

	sys, err = ts.Store.ReadAccountClaim("SYS")
	require.NoError(t, err)

	require.False(t, sys.Limits.IsJSEnabled())
}

func Test_RouteSelfClusterTraffic(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, jwt.ClusterTraffic(""), ac.ClusterTraffic)

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--host-cluster-traffic"}...)
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, jwt.ClusterTraffic(jwt.ClusterTrafficOwner), ac.ClusterTraffic)

	_, err = ExecuteCmd(createEditAccount(), []string{"A", "--host-cluster-traffic=false"}...)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, jwt.ClusterTraffic(""), ac.ClusterTraffic)
}
