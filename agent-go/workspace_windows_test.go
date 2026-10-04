package main

import (
	"testing"
	"time"
)

func TestWorkspaceCloseHitBounds(t *testing.T) {
	b := uiRect{0, 0, 56, 56}
	for _, p := range []workspacePoint{{0, 0}, {28, 28}, {55, 55}} {
		if !workspacePointInside(b, p.X, p.Y) {
			t.Fatal("close hit rejected", p)
		}
	}
	for _, p := range []workspacePoint{{-1, 28}, {28, -1}, {56, 28}, {28, 56}} {
		if workspacePointInside(b, p.X, p.Y) {
			t.Fatal("cancelled close drag accepted", p)
		}
	}
}

func TestWorkspaceOpeningFadeIsBoundedAndMonotonic(t *testing.T) {
	last := byte(0)
	for elapsed := -20 * time.Millisecond; elapsed <= 250*time.Millisecond; elapsed += 5 * time.Millisecond {
		alpha := workspaceFadeAlpha(elapsed)
		if alpha < 180 || alpha < last {
			t.Fatalf("invalid opening fade at %s: %d after %d", elapsed, alpha, last)
		}
		last = alpha
	}
	if workspaceFadeAlpha(0) != 180 || workspaceFadeAlpha(180*time.Millisecond) != 255 {
		t.Fatal("fade endpoints changed")
	}
}

func TestRadialMenuFitsAndFutureModulesAreDisabled(t *testing.T) {
	for _, diameter := range []int32{240, 280, 320} {
		items := workspaceMenuItems(diameter)
		if len(items) != 5 {
			t.Fatal("unexpected radial actions")
		}
		seen := map[uintptr]bool{}
		for _, item := range items {
			if seen[item.id] {
				t.Fatal("duplicate action")
			}
			seen[item.id] = true
			if item.x < 0 || item.y < 0 || item.x+item.size > diameter || item.y+item.size > diameter {
				t.Fatalf("radial action clipped: %+v", item)
			}
			if item.disabled != (item.id == 105 || item.id == 106) {
				t.Fatalf("future module accidentally enabled: %+v", item)
			}
		}
	}
}

func TestWorkspaceBoundsStayInsideSmallAndNegativeOriginScreens(t *testing.T) {
	cases := []struct {
		work       uiRect
		x, y, w, h int32
	}{
		{uiRect{0, 0, 320, 480}, 900, -100, 340, 360},
		{uiRect{-1280, 0, 0, 720}, -1500, 690, 340, 360},
		{uiRect{0, -800, 1024, 0}, 100, -900, 52, 52},
		{uiRect{0, 0, 240, 300}, 0, 0, 340, 360},
	}
	for _, c := range cases {
		got := workspaceBounds(c.work, c.x, c.y, c.w, c.h)
		if got.Left < c.work.Left || got.Top < c.work.Top || got.Right > c.work.Right || got.Bottom > c.work.Bottom {
			t.Fatalf("workspace escapes work area: %+v in %+v", got, c.work)
		}
	}
}
