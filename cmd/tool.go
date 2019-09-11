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
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

var toolCmd = &cobra.Command{
	Use:   "tool",
	Short: "NATS tools: pub, sub, req, rep, rtt",
}

var natsURLFlag = ""

func init() {
	toolCmd.PersistentFlags().StringVarP(&natsURLFlag, "nats", "", "", "nats url, defaults to the operator's service URLs")
	GetRootCmd().AddCommand(toolCmd)
}

func createDefaultToolOptions(name string, ctx ActionCtx) []nats.Option {
	connectTimeout := 5 * time.Second
	totalWait := 10 * time.Minute
	reconnectDelay := 2 * time.Second

	opts := []nats.Option{nats.Name(name)}
	opts = append(opts, nats.Timeout(connectTimeout))
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
	return opts
}
