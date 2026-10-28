# Assets manifest

| Path | Purpose | Dimensions |
|---|---|---|
| `active-mark-128.png` | G0 small raster export | 128x128 |
| `active-mark-512.png` | G0 raster export | 512x512 |
| `active-mark.png` | Approved Active mark, byte-identical source | 460x460 |
| `active-mark.svg` | G0 vector wrapper embedding the approved mark | 512x512 |
| `control-plane-dark.png` | Live dashboard screenshot (dark) with Live activity, 20 real gauges, engines and event log | 1320x917 |
| `control-plane-light.png` | Live dashboard screenshot (light) with Live activity, 20 real gauges, engines and event log | 1320x917 |
| `control-plane-gauges-dark.png` | Live gauge grid (dark): 20 source-labelled gauges from the running plane | 1320x917 |
| `control-plane-gauges-light.png` | Live gauge grid (light): 20 source-labelled gauges from the running plane | 1320x917 |
| `control-plane-benchmark-dark.png` | Benchmark desk and Agent access panels (dark) after a real 40-iteration run | 1320x917 |
| `control-plane-benchmark-light.png` | Benchmark desk and Agent access panels (light) after a real 40-iteration run | 1320x917 |
| `control-plane-mcp-dark.png` | Agent access and MCP configuration panel (dark) | 1320x917 |
| `control-plane-mcp-light.png` | Agent access and MCP configuration panel (light) | 1320x917 |
| `../../control-plane/public/assets/gauge-frame.svg` | D2 reusable gauge bezel, exported from Figma frame 1:20 | 260x160 |
| `../../control-plane/public/assets/lane-icon.svg` | D3 lane metaphor icon, exported from Figma frame 1:25 | 64x64 |
| `../../control-plane/public/assets/channel-icon.svg` | D4 channel metaphor icon, exported from Figma frame 1:29 | 64x64 |
| `../../control-plane/public/assets/cap-icon.svg` | D5 capability token icon, exported from Figma frame 1:34 | 64x64 |
| `../../control-plane/public/assets/packet-flow.svg` | D6 packet-flow motif, exported from Figma frame 1:40 | 320x72 |
| `readme-arch-rpc-dark.png` | README theme asset | 1320x462 |
| `readme-arch-rpc-dark.svg` | README theme asset | 2400x840 |
| `readme-arch-rpc-light.png` | README theme asset | 1320x462 |
| `readme-arch-rpc-light.svg` | README theme asset | 2400x840 |
| `readme-banner-rpc-dark.png` | README theme asset | 1320x462 |
| `readme-banner-rpc-dark.svg` | README theme asset | 2400x840 |
| `readme-banner-rpc-light.png` | README theme asset | 1320x462 |
| `readme-banner-rpc-light.svg` | README theme asset | 2400x840 |
| `readme-compare-rpc-dark.png` | README theme asset | 1320x462 |
| `readme-compare-rpc-dark.svg` | README theme asset | 2400x840 |
| `readme-compare-rpc-light.png` | README theme asset | 1320x462 |
| `readme-compare-rpc-light.svg` | README theme asset | 2400x840 |

All README images are authored at 2400x840 and exported losslessly at 1320x462
(1.5x GitHub README width) to stay inside the 500 KB budget. Light/dark pairs
are separate files; the README selects them with `<picture>` and
`prefers-color-scheme`. GitHub's deprecated `#gh-` fragments are not used;
that deviation is recorded in the package and goal notes. The palette is the active-lang
header: #101016 charcoal, #f2571f orange, #a0a7b0 gray, flat surfaces, no
gradients. The approved mark `active-mark.png` is an exact byte copy of
active-lang's `docs/assets/active-icon.png`
(SHA-256 AF10D633E0C19B6EF069FF29820C84B355006CE384050D140FCF52A20E9CA1D2).

## Figma source

File: <https://www.figma.com/design/nyTzKiMl36weqEd8KUm1EM> (`Active-World-Presence`).

Pages: `Brand` holds all 22 exported assets at source resolution; `README` and
`Dashboard` are reserved. The Starter plan allows three pages, so the brief's
four-page split is represented as Brand + README + Dashboard.

## Capture provenance

`control-plane-{light,dark}.png` and `control-plane-gauges-{light,dark}.png` were
captured from the real `active-control-plane` service (active-rpc 2.0.0,
active-infinity 2.1.0) with Playwright Chromium at a 1320x917 viewport after
running the full L0-L6 ladder and a 40-iteration benchmark. The page reported
zero console and zero page errors.
