// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "testing"

func TestAllow(t *testing.T) {
	if !allowed.Match("/bytes/122") {
		t.Error("/bytes")
	}
	if !allowed.Match("/tags?query=val") {
		t.Error("/tags")
	}
	if !allowed.Match("/peers") {
		t.Error("/peers")
	}
}

func TestForbid(t *testing.T) {
	if !forbidden.Match("/debug/pprof/heap") {
		t.Error("/heap")
	}
	if !forbidden.Match("/debug/pprof/cpu") {
		t.Error("/cpu")
	}
	if !forbidden.Match("/node") {
		t.Error("/node")
	}
}
