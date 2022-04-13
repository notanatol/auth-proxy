// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"regexp"
)

type matcher []string

func (w matcher) Match(url string) bool {
	for _, path := range w {
		match, _ := regexp.MatchString(path, url) // TODO optimize with cached matchers
		if match {
			return true
		}
	}
	return false
}

var allowed = matcher([]string{
	"/bytes",
	"/bytes/*",
	"/chunks",
	"/chunks/*",
	"/bzz*",
	"/tags*",
	"/pins*",
	"/pss/send/*",
	"/pss/subscribe/*",
	"/soc/*",
	"/feeds/*",
	"/stamps",
	"/stamps/*",
	"/stamps/topup/*",
	"/stamps/dilute/*",
	"/addresses",
	"/blocklist",
	"/connect/*",
	"/peers",
	"/peers/*",
	"/pingpong/*",
	"/topology",
	"/welcome-message",
	"/balances",
	"/balances/*",
	"/chequebook/cashout/*",
	"/chequebook/cashout/*",
	"/chequebook/withdraw*",
	"/chequebook/deposit*",
	"/chequebook/cheque*",
	"/chequebook/address",
	"/chequebook/balance",
	"/chunks/*",
	"/reservestate",
	"/chainstate",
	"/settlements",
	"/settlements/*",
	"/transactions",
	"/transactions/*",
	"/consumed",
	"/consumed/*",
	"/chunks/stream",
	"/stewardship/*",
})

var forbidden = matcher([]string{
	"/node",
	"/health",
	"/readiness",
	"/debug/*",
})
