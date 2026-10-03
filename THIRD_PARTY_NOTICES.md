# Third party notices

Warden uses third-party software and data. Their copyright notices and licenses remain in force independently of Warden's own source-code licenses. This acknowledgment does not change the license of Warden or imply endorsement by upstream maintainers.

The collected upstream texts are in [third_party/licenses](third_party/licenses). The [machine-readable inventory](third_party/inventory.json) records the declared Go modules, installed development Python distributions and bundled browser assets reviewed on 3 October 2026. Original source-file hashes may differ after line-ending normalization. This inventory is not a complete container SBOM or a legal-compliance certification.

## Browser assets and fonts

| Component | Version or asset | License | Upstream |
| --- | --- | --- | --- |
| Alpine CSP | 3.17.4 | MIT | [Alpine](https://github.com/alpinejs/alpine) |
| HTMX | 1.9.12 | 0BSD | [HTMX](https://github.com/bigskysoftware/htmx) |
| Chart.js | 4.4.4 | MIT | [Chart.js](https://github.com/chartjs/Chart.js) |
| Tailwind CSS | 3.4.17, compiled at build time | MIT | [Tailwind](https://github.com/tailwindlabs/tailwindcss) |
| Inter | Vendored font assets | SIL Open Font License 1.1 | [Inter](https://github.com/rsms/inter) |
| JetBrains Mono | Vendored font assets | SIL Open Font License 1.1 | [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) |

Browser and font license texts are also stored beside the server's static assets so the server image includes them. Font package/revision provenance must be confirmed against the exact font artifacts before a release; the upstream font notices are retained here without inventing a package version.

## Agent and Home dependencies

The Windows agent and Home use Gorilla WebSocket, NetBird's go-nat, Pion ICE/WebRTC and Go's supplementary libraries. Device metrics use gopsutil. NetBird's go-nat is Apache-2.0; do not substitute the license of the separate NetBird application. Pion includes additional per-file license texts which are retained in the collected LICENSES directories. The native Warden prompts use Windows APIs rather than an additional third-party GUI framework.

| Go module | Declared version | Collected license texts |
| --- | --- | --- |
| `github.com/gorilla/websocket` | `v1.5.3` | [License directory](third_party/licenses/go/github.com_gorilla_websocket@v1.5.3) |
| `github.com/netbirdio/go-nat` | `v0.0.0-20260821095157-6b2c8c5c74e8` | [License directory](third_party/licenses/go/github.com_netbirdio_go-nat@v0.0.0-20260821095157-6b2c8c5c74e8) |
| `github.com/pion/ice/v4` | `v4.4.4` | [License directory](third_party/licenses/go/github.com_pion_ice_v4@v4.4.4) |
| `github.com/pion/webrtc/v4` | `v4.2.22` | [License directory](third_party/licenses/go/github.com_pion_webrtc_v4@v4.2.22) |
| `github.com/shirou/gopsutil/v3` | `v3.24.5` | [License directory](third_party/licenses/go/github.com_shirou_gopsutil_v3@v3.24.5) |
| `golang.org/x/sys` | `v0.48.0` | [License directory](third_party/licenses/go/golang.org_x_sys@v0.48.0) |
| `github.com/go-ole/go-ole` | `v1.2.6` | [License directory](third_party/licenses/go/github.com_go-ole_go-ole@v1.2.6) |
| `github.com/google/gopacket` | `v1.1.19` | [License directory](third_party/licenses/go/github.com_google_gopacket@v1.1.19) |
| `github.com/google/uuid` | `v1.6.0` | [License directory](third_party/licenses/go/github.com_google_uuid@v1.6.0) |
| `github.com/huin/goupnp` | `v1.2.0` | [License directory](third_party/licenses/go/github.com_huin_goupnp@v1.2.0) |
| `github.com/jackpal/go-nat-pmp` | `v1.0.2` | [License directory](third_party/licenses/go/github.com_jackpal_go-nat-pmp@v1.0.2) |
| `github.com/koron/go-ssdp` | `v0.0.4` | [License directory](third_party/licenses/go/github.com_koron_go-ssdp@v0.0.4) |
| `github.com/libp2p/go-netroute` | `v0.2.1` | [License directory](third_party/licenses/go/github.com_libp2p_go-netroute@v0.2.1) |
| `github.com/lufia/plan9stats` | `v0.0.0-20211012122336-39d0f177ccd0` | [License directory](third_party/licenses/go/github.com_lufia_plan9stats@v0.0.0-20211012122336-39d0f177ccd0) |
| `github.com/pion/datachannel` | `v1.6.3` | [License directory](third_party/licenses/go/github.com_pion_datachannel@v1.6.3) |
| `github.com/pion/dtls/v3` | `v3.1.9` | [License directory](third_party/licenses/go/github.com_pion_dtls_v3@v3.1.9) |
| `github.com/pion/interceptor` | `v0.1.49` | [License directory](third_party/licenses/go/github.com_pion_interceptor@v0.1.49) |
| `github.com/pion/logging` | `v0.2.4` | [License directory](third_party/licenses/go/github.com_pion_logging@v0.2.4) |
| `github.com/pion/mdns/v2` | `v2.2.1` | [License directory](third_party/licenses/go/github.com_pion_mdns_v2@v2.2.1) |
| `github.com/pion/randutil` | `v0.1.0` | [License directory](third_party/licenses/go/github.com_pion_randutil@v0.1.0) |
| `github.com/pion/rtcp` | `v1.2.18` | [License directory](third_party/licenses/go/github.com_pion_rtcp@v1.2.18) |
| `github.com/pion/rtp` | `v1.10.5` | [License directory](third_party/licenses/go/github.com_pion_rtp@v1.10.5) |
| `github.com/pion/sctp` | `v1.11.3` | [License directory](third_party/licenses/go/github.com_pion_sctp@v1.11.3) |
| `github.com/pion/sdp/v3` | `v3.0.20` | [License directory](third_party/licenses/go/github.com_pion_sdp_v3@v3.0.20) |
| `github.com/pion/srtp/v3` | `v3.1.0` | [License directory](third_party/licenses/go/github.com_pion_srtp_v3@v3.1.0) |
| `github.com/pion/stun/v4` | `v4.0.1` | [License directory](third_party/licenses/go/github.com_pion_stun_v4@v4.0.1) |
| `github.com/pion/transport/v5` | `v5.1.1` | [License directory](third_party/licenses/go/github.com_pion_transport_v5@v5.1.1) |
| `github.com/pion/turn/v5` | `v5.1.2` | [License directory](third_party/licenses/go/github.com_pion_turn_v5@v5.1.2) |
| `github.com/power-devops/perfstat` | `v0.0.0-20210106213030-5aafc221ea8c` | [License directory](third_party/licenses/go/github.com_power-devops_perfstat@v0.0.0-20210106213030-5aafc221ea8c) |
| `github.com/shoenig/go-m1cpu` | `v0.1.6` | [License directory](third_party/licenses/go/github.com_shoenig_go-m1cpu@v0.1.6) |
| `github.com/tklauser/go-sysconf` | `v0.3.12` | [License directory](third_party/licenses/go/github.com_tklauser_go-sysconf@v0.3.12) |
| `github.com/tklauser/numcpus` | `v0.6.1` | [License directory](third_party/licenses/go/github.com_tklauser_numcpus@v0.6.1) |
| `github.com/wlynxg/anet` | `v0.0.5` | [License directory](third_party/licenses/go/github.com_wlynxg_anet@v0.0.5) |
| `github.com/yusufpapurcu/wmi` | `v1.2.4` | [License directory](third_party/licenses/go/github.com_yusufpapurcu_wmi@v1.2.4) |
| `golang.org/x/crypto` | `v0.57.0` | [License directory](third_party/licenses/go/golang.org_x_crypto@v0.57.0) |
| `golang.org/x/net` | `v0.59.0` | [License directory](third_party/licenses/go/golang.org_x_net@v0.59.0) |
| `golang.org/x/sync` | `v0.2.0` | [License directory](third_party/licenses/go/golang.org_x_sync@v0.2.0) |
| `golang.org/x/time` | `v0.14.0` | [License directory](third_party/licenses/go/golang.org_x_time@v0.14.0) |
| `golang.org/x/sys` | `v0.44.0` | [License directory](third_party/licenses/go/golang.org_x_sys@v0.44.0) |

## Server and builder dependencies

Python entries below describe the isolated development images, including transitive packages. Direct version pins are authoritative in server/requirements.txt and build-service/requirements.txt. Rebuild the inventory for every released image rather than assuming its transitive versions match this snapshot.

| Python distribution | Observed version | License declaration |
| --- | --- | --- |
| `bcrypt` | `4.2.0` | Apache-2.0 |
| `blinker` | `1.9.0` | See license files |
| `cffi` | `2.1.1` | MIT-0 |
| `click` | `8.5.0` | BSD-3-Clause |
| `cryptography` | `50.0.0` | Apache-2.0 OR BSD-3-Clause |
| `Deprecated` | `3.0.0` | MIT |
| `Flask` | `3.1.3` | BSD-3-Clause |
| `Flask-Limiter` | `3.8.0` | MIT |
| `gunicorn` | `22.0.0` | MIT |
| `itsdangerous` | `2.2.0` | See license files |
| `Jinja2` | `3.1.6` | See license files |
| `limits` | `5.8.0` | MIT |
| `markdown-it-py` | `4.2.0` | See license files |
| `MarkupSafe` | `3.0.4` | BSD-3-Clause |
| `mdurl` | `0.1.2` | See license files |
| `ordered-set` | `4.1.0` | See license files |
| `packaging` | `26.3` | Apache-2.0 OR BSD-2-Clause |
| `pillow` | `12.3.0` | MIT-CMU |
| `pip` | `25.0.1` | MIT |
| `psycopg2-binary` | `2.9.9` | LGPL with exceptions |
| `pycparser` | `3.0` | BSD-3-Clause |
| `Pygments` | `2.21.0` | BSD-2-Clause |
| `PyJWT` | `2.15.1` | MIT |
| `pyotp` | `2.9.0` | MIT License |
| `python-magic` | `0.4.27` | MIT |
| `qrcode` | `8.2` | BSD |
| `rich` | `13.9.4` | MIT |
| `typing_extensions` | `4.16.0` | PSF-2.0 |
| `websockets` | `17.1` | BSD-3-Clause |
| `Werkzeug` | `3.1.9` | BSD-3-Clause |
| `wrapt` | `2.5.0` | BSD-2-Clause |
| `certifi` | `2026.7.22` | MPL-2.0 |
| `charset-normalizer` | `3.5.2` | MIT |
| `idna` | `3.20` | BSD-3-Clause |
| `requests` | `2.34.2` | Apache-2.0 |
| `urllib3` | `2.8.0` | MIT |

## Data and platform components

Unicode CLDR timezone mapping data has an existing [Unicode notice](server/services/data/UNICODE_LICENSE.txt); retain it when distributing the mapping. Go and Python standard libraries, PostgreSQL, PostgREST, operating-system packages, Windows runtime components and native libraries embedded in Python wheels have their own terms. The dependency inventory above does not replace the exact image or binary SBOM and its notices.

Optional external tools or user-uploaded application packages are not automatically covered by Warden's notices. Before bundling one, verify its exact version, origin, license and redistribution requirements. An optional module must carry its own dependency notices; separating modules does not remove license obligations.

## Release requirements

- Preserve copyright notices, complete applicable license texts and upstream NOTICE files. Credits or links alone are not a substitute for redistribution requirements.
- Review source/relinking obligations for psycopg2 and its LGPL-with-exceptions license, file-level obligations for certifi's MPL-covered certificate bundle, and the SIL font license requirements against the actual distribution. Obtain legal review when uncertain.
- Include the relevant notices with every source archive, server image, agent/Home installer and separately distributed module. Current binary packaging still needs an artifact-level check; this document does not assert that existing published installers already contain this new notice bundle.
- Produce an SBOM for each artifact and review native dependencies bundled in wheels and base images. Do not infer the license of a complete project from one dependency or license identifier.
- Review Windows SDK, credential-provider, remote-access, packet-capture and networking components separately when they are included in an artifact. Preserve their applicable notices in an SPDX or CycloneDX release SBOM.
- Refresh third_party/inventory.json when dependencies change and run `python tools/check_third_party.py`. This check detects missing declared dependencies or notice files; it is not legal approval, vulnerability scanning or proof of binary-package compliance.
