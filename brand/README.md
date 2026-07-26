# Braid brand assets

The mark is two squircles offset along the diagonal, drawn as one path with
`fill-rule="evenodd"` so the region they share knocks out. Two separate
contexts overlapping; what they hold in common is the braid. It carries no
letterform, so it does not need to change if the name ever does.

| File | Use |
| --- | --- |
| `braid-mark.svg` | Mark alone, light backgrounds |
| `braid-mark-dark.svg` | Mark alone, dark backgrounds |
| `braid-lockup.svg` | Mark + wordmark, light |
| `braid-lockup-dark.svg` | Mark + wordmark, dark |
| `braid-badge.svg` | Rounded-square app/favicon badge |
| `construction-sheet.html` | Grid and geometry reference |

The website ships its own inline copies rather than importing these:
`components/ui/logo.tsx` (mark) and `app/icon.svg` (badge). Keep them in sync
by hand — they are duplicated deliberately so the site has no asset
dependency on this repo.

## Before using the lockups publicly

**The wordmark is live `<text>`, not outlined.** It requests Inter first and
falls back to Helvetica/Arial, so on any machine without Inter installed the
lockup renders in a different typeface. Outline it to paths before putting it
anywhere public — a press kit, an OG image, a conference slide — and re-trim
the `viewBox` width to the real ink afterwards. The current width is an
estimate from Inter Bold advance widths, not a measurement.

The mark and badge have no type in them and are safe to use as-is.

## archive-nexus-n-monogram/

An earlier identity built as a letterform **N** for the name "Nexus", kept only
for reference. It cannot be used for Braid — the mark is literally the wrong
letter.
