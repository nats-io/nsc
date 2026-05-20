// Copyright 2018-2019 The NATS Authors
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
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

var toolCmd = &cobra.Command{
	Use:   "tool",
	Short: "NATS tools: pub, sub, req, reply, rtt",
}

type tlsConfig struct {
	tlsFirst bool
	ca       string
	cert     string
	key      string
	curves   string
}

// parseTLSCurves parses a comma-separated list of TLS curve names.
// Accepted names: P256, P384, P521, X25519 (case-insensitive,
// "Curve" prefix optional).
func parseTLSCurves(s string) ([]tls.CurveID, error) {
	if s == "" {
		return nil, nil
	}
	var out []tls.CurveID
	for _, raw := range strings.Split(s, ",") {
		name := strings.TrimSpace(raw)
		name = strings.TrimPrefix(strings.ToLower(name), "curve")
		switch name {
		case "p256":
			out = append(out, tls.CurveP256)
		case "p384":
			out = append(out, tls.CurveP384)
		case "p521":
			out = append(out, tls.CurveP521)
		case "x25519":
			out = append(out, tls.X25519)
		default:
			return nil, fmt.Errorf("unknown TLS curve %q (accepted: P256, P384, P521, X25519)", raw)
		}
	}
	return out, nil
}

// tlsCurvesOption returns a nats.Option that sets CurvePreferences on the
// connection's TLSConfig, allocating one if needed and preserving any other
// fields populated by RootCAs/ClientCert callbacks.
func tlsCurvesOption(curves []tls.CurveID) nats.Option {
	return func(o *nats.Options) error {
		if o.TLSConfig == nil {
			o.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		o.TLSConfig.CurvePreferences = curves
		return nil
	}
}

var natsURLFlag = ""
var encryptFlag bool
var clienttls tlsConfig

// bindClientTLSFlags registers the shared --tls-first/--ca-cert/--client-cert/
// --client-key/--tls-curves flags on the given flag set. Used by tool, push
// and pull commands so they all expose the same TLS surface.
func bindClientTLSFlags(flags *flag.FlagSet) {
	flags.BoolVarP(&clienttls.tlsFirst, "tls-first", "", false, "use tls-first when connecting to the nats server")
	flags.StringVarP(&clienttls.ca, "ca-cert", "", "", "ca certificate file for tls connections")
	flags.StringVarP(&clienttls.cert, "client-cert", "", "", "client certificate file for tls connections")
	flags.StringVarP(&clienttls.key, "client-key", "", "", "client key file for tls connections")
	flags.StringVarP(&clienttls.curves, "tls-curves", "", "", "comma-separated TLS curve preferences (e.g. P256,P384,P521); defaults to Go's TLS defaults")
}

func init() {
	toolCmd.PersistentFlags().StringVarP(&natsURLFlag, "nats", "", "", "nats url, defaults to the operator's service URLs")
	bindClientTLSFlags(toolCmd.PersistentFlags())
	GetRootCmd().AddCommand(toolCmd)
}

func createDefaultToolOptions(name string, ctx ActionCtx, o ...nats.Option) []nats.Option {
	connectTimeout := 5 * time.Second
	totalWait := 10 * time.Minute
	reconnectDelay := 2 * time.Second

	opts := []nats.Option{nats.Name(name)}
	opts = append(opts, nats.Timeout(connectTimeout))
	opts = append(opts, rootCAsNats)
	opts = append(opts, tlsKeyNats)
	opts = append(opts, tlsCertNats)
	opts = append(opts, nats.ReconnectWait(reconnectDelay))
	opts = append(opts, nats.MaxReconnects(int(totalWait/reconnectDelay)))
	opts = append(opts, nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
		if err != nil {
			ctx.CurrentCmd().Printf("Disconnected: error: %v\n", err)
		}
		if nc.Status() == nats.CLOSED {
			return
		}
		ctx.CurrentCmd().Printf("Disconnected: will attempt reconnects for %.0fm", totalWait.Minutes())
	}))
	opts = append(opts, nats.ReconnectHandler(func(nc *nats.Conn) {
		ctx.CurrentCmd().Printf("Reconnected [%s]", nc.ConnectedUrl())
	}))
	opts = append(opts, nats.ClosedHandler(func(nc *nats.Conn) {
		if nc.Status() == nats.CLOSED {
			return
		}
		ctx.CurrentCmd().Printf("Exiting, no servers available, or connection closed")
	}))
	if clienttls.tlsFirst {
		opts = append(opts, nats.TLSHandshakeFirst())
	}
	if clienttls.ca != "" {
		opts = append(opts, nats.RootCAs(clienttls.ca))
	}
	if clienttls.cert != "" || clienttls.key != "" {
		opts = append(opts, nats.ClientCert(clienttls.cert, clienttls.key))
	}
	if clienttls.curves != "" {
		curves, err := parseTLSCurves(clienttls.curves)
		if err != nil {
			opts = append(opts, func(*nats.Options) error { return err })
		} else {
			opts = append(opts, tlsCurvesOption(curves))
		}
	}
	opts = append(opts, o...)
	return opts
}
