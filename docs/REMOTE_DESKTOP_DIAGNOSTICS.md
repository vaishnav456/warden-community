# Remote desktop input and frame measurements

The viewer reports displayed FPS, time since its last paint, and relay round-trip
time separately. Frame age is not a measurement of how long a click took to reach
the computer. An unchanged desktop can send periodic repeated snapshots.

Hover over the viewer's FPS display to inspect these boundaries:

| Measurement | What it proves |
| --- | --- |
| Server frames received | Binary application messages yielded by the agent socket before forwarding |
| Server frames forwarded | Successful sends to the browser socket, without a browser acknowledgement |
| Browser received FPS | Frames delivered to the viewer's message handler |
| Displayed FPS | Frames painted by the viewer |
| Accepted control inputs | Known control operations allowed by the session capability checks |
| Forwarded control inputs | Successful sends to the agent socket, without an agent acknowledgement |
| Agent input dispatch | Attempts to handle an input in the desktop helper |
| Windows input accepted | Native cursor/input calls reported success; this does not acknowledge an application's response |

Agent 2.6.62 adds native input outcomes. Older agents' version 1 reports remain
supported and do not claim to measure Windows acceptance. The viewer shows a
notice when a fresh version 2 helper report contains rejected input attempts.
Windows can refuse input to another desktop or a higher-integrity application;
these diagnostics do not change Windows privileges or security settings.

Capture and service reports describe separate sampling windows. Readback samples
include failed attempts. DXGI frame counts include repeated cached snapshots, so
the tooltip shows repeats, idle acquisitions, readback attempts, window length
and helper report age. Their counts should not be compared as if the windows
were synchronized.

The server retains at most 12 validated numeric agent reports for at most 90
seconds in each live session. The existing encrypted quality receipt includes
that short history; ordinary relay pongs omit it. Reports contain counters,
dimensions and timing summaries, without screen images, coordinates, key contents
or clipboard contents. In-memory collection stops when the session closes; its
final encrypted quality receipt follows the normal session-record retention.

The viewer releases its held mouse buttons on pointer-capture loss, navigation,
disconnect, helper initialization and entry to view-only mode. The agent resets
mouse buttons when its desktop helper starts and exits normally. Abrupt process
termination can prevent exit cleanup; the next helper's startup reset remains
necessary.

For a performance investigation, record a continuous period of actual movement
and compare the corresponding numeric report history. A low FPS reading after
movement has stopped is insufficient to locate a bottleneck. Database reads and
quality writes run separately from active frame and control forwarding.
