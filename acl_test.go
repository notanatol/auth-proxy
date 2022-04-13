// Copyright 2022 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "testing"

func TestAllow(t *testing.T) {
	if !allow.Match("/bytes/122") {
		t.Error("/bytes")
	}
	if !allow.Match("/tags?query=val") {
		t.Error("/tags")
	}
	if !allow.Match("/peers") {
		t.Error("/peers")
	}
}

func TestForbid(t *testing.T) {
	if forbid.Match("/debug/pprof/heap") {
		t.Error("/heap")
	}
	if forbid.Match("/debug/pprof/cpu") {
		t.Error("/cpu")
	}
	if forbid.Match("/node") {
		t.Error("/node")
	}
}
