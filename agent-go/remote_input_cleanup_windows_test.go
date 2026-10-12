package main

import (
	"reflect"
	"testing"
)

func TestRemoteMouseCleanupReleasesEveryButtonWithoutMovingEvenAfterNativeFailure(t *testing.T) {
	type call struct {
		x, y        int32
		flags, data uint32
	}
	var calls []call
	send := func(x, y int32, flags, data uint32) bool {
		calls = append(calls, call{x, y, flags, data})
		return flags != mouseLeftUp
	}
	// Each helper startup/exit reset must attempt all releases independently.
	releaseRemoteMouseButtonsWith(send)
	releaseRemoteMouseButtonsWith(send)
	want := []call{{0, 0, mouseLeftUp, 0}, {0, 0, mouseRightUp, 0}, {0, 0, mouseMidUp, 0}}
	want = append(want, want...)
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup introduced move/down or skipped a release: %#v", calls)
	}
}

func TestRemoteNativeInputAcceptanceAndReleaseOrder(t *testing.T) {
	for _, kind := range []string{"mousedown", "mouseup"} {
		for _, button := range []string{"left", "right", "middle"} {
			for _, outcomes := range [][2]bool{{true, true}, {false, true}, {true, false}, {false, false}} {
				t.Run(kind+"/"+button, func(t *testing.T) {
					var order []string
					var mouseFlags uint32
					api := remoteInputNativeAPI{
						cursor: func(x, y int32) bool {
							if x != -31 || y != 72 {
								t.Fatalf("native position changed: %d,%d", x, y)
							}
							order = append(order, "cursor")
							return outcomes[0]
						},
						mouse: func(x, y int32, flags, data uint32) bool {
							if x != 0 || y != 0 || data != 0 {
								t.Fatal("button event moved or added data")
							}
							mouseFlags = flags
							order = append(order, "button")
							return outcomes[1]
						},
					}
					attempted, accepted := dispatchInputWith(map[string]interface{}{"type": kind, "button": button, "x": float64(9), "y": float64(12)}, monitorRect{Left: -40, Top: 60}, api)
					if !attempted || accepted != (outcomes[0] && outcomes[1]) || !reflect.DeepEqual(order, []string{"cursor", "button"}) {
						t.Fatalf("wrong native acknowledgement/order: %v/%v %v", attempted, accepted, order)
					}
					flags := map[string]uint32{"left": mouseLeftDown, "right": mouseRightDown, "middle": mouseMidDown}
					if kind == "mouseup" {
						flags = map[string]uint32{"left": mouseLeftUp, "right": mouseRightUp, "middle": mouseMidUp}
					}
					if mouseFlags != flags[button] {
						t.Fatalf("wrong button transition: %#x", mouseFlags)
					}
				})
			}
		}
	}
}

func TestRemoteNativeInputOutcomeExcludesMetadataAndUnknownKeys(t *testing.T) {
	for _, success := range []bool{false, true} {
		api := remoteInputNativeAPI{cursor: func(int32, int32) bool { return success }, mouse: func(int32, int32, uint32, uint32) bool { return success }, key: func(uint16, uint32) bool { return success }, unicode: func(string, uint32) bool { return success }}
		for _, event := range []map[string]interface{}{
			{"type": "mousemove", "x": float64(1), "y": float64(2)},
			{"type": "scroll", "delta": float64(1)},
			{"type": "keydown", "key": "a", "code": "KeyA"},
			{"type": "keyup", "key": "a", "code": "KeyA"},
			{"type": "keydown", "key": "@"},
		} {
			attempted, accepted := dispatchInputWith(event, monitorRect{}, api)
			if !attempted || accepted != success {
				t.Fatalf("outcome wrong for %s: %v/%v", event["type"], attempted, accepted)
			}
		}
		for _, event := range []map[string]interface{}{{"type": "viewport_size"}, {"type": "monitor_select"}, {"type": "keydown", "key": "Unidentified"}, {"type": "unknown"}} {
			attempted, accepted := dispatchInputWith(event, monitorRect{}, remoteInputNativeAPI{})
			if attempted || accepted {
				t.Fatalf("non-native event was acknowledged: %s", event["type"])
			}
		}
	}
}
