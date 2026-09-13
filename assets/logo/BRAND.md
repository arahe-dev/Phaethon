# Phaethon brand

## The mark

Two routes leave the same point. One continues straight; the other diverts and
is drawn in the accent colour.

That is the product in one glyph. Phaethon keeps healthy traffic on the direct
path and intervenes only where the direct path is broken — so the mark shows a
split, not a tunnel. A tunnel would say "everything goes through me", which is
the design Phaethon exists to avoid.

The kraft dot at the origin is the nod to the mascot: the parcel that gets
patched up and sent anyway.

## Colours

| Role | Dark | Light | Notes |
| --- | --- | --- | --- |
| Direct path | `#f2f0eb` | `#2b2f36` | Neutral: the healthy path is not special |
| Diverted path | `#d4e619` | `#8f9c00` | The accent, taken from the mascot's eyes |
| Origin | `#b5905f` | `#b5905f` | Kraft, from the bag |
| Background | `#0d1117` | `#ffffff` | GitHub's own dark and light |

The accent is the only saturated colour in the system. It marks intervention and
nothing else, so a reader can find the interesting path without being told.

## Assets

| File | Use |
| --- | --- |
| `phaethon-lockup-{dark,light}.svg` | README header, docs splash |
| `phaethon-wordmark-{dark,light}.svg` | Anywhere the mark is already present |
| `phaethon-mark-{dark,light}.svg` | App icon, social preview, favicon |
| `concepts/` | The three directions considered, kept for the record |
| `../hero-phaethon.webp` | The mascot, as supplied |

Every asset ships as a light and dark variant, so both GitHub themes read
correctly with `#gh-dark-mode-only` / `#gh-light-mode-only` suffixes.

## Concepts considered

1. **Split path** — chosen. Reads at 24px, states the product, no letterform dependency.
2. **Mask and eyes** — closest to the mascot, but at small sizes it becomes a
   brown rectangle, and it says "face", not "routing".
3. **P with a cut-through** — states the name, but the notch reads as a rendering
   error at icon sizes and the letterform leaves no room for the accent.

## Limits of what is here

These are hand-authored SVGs, not a designed brand. The wordmark uses live text
rather than outlined paths, so it depends on a sans-serif face being available
and should be outlined before any use where the typography matters. There is no
raster export, no social preview image, and no app icon set.
