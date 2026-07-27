# Braid brand assets

The mark is two squircles offset along the diagonal, drawn as one path with
`fill-rule="evenodd"` so the region they share knocks out. Two separate
contexts overlapping; what they hold in common is the braid. It carries no
letterform, so it does not need to change if the name ever does.

Built on the 48-unit grid: two 28u squircles at `rx 8`, offset 11u, scaled by
30/39 to a 30u ink extent. Three features (two regions, one hole) against a
corpus median of two, and the hole survives a 16px render. Brand colour
`#4F46E5` indigo-600.

| File | Use |
| --- | --- |
| `braid-mark.svg` | Mark alone, light backgrounds |
| `braid-mark-dark.svg` | Mark alone, dark backgrounds |
| `braid-lockup.svg` | Mark + wordmark, light |
| `braid-lockup-dark.svg` | Mark + wordmark, dark |
| `braid-badge.svg` | Rounded-square app/favicon badge |
| `construction-sheet.html` | Grid and geometry proof — open it, the numbers compute live |

The website ships its own inline copies rather than importing these:
`components/ui/logo.tsx` (mark) and `app/icon.svg` (badge). Keep them in sync
by hand — they are duplicated deliberately so the site has no asset dependency
on this repo.

## Before using the lockups publicly

**The wordmark is live `<text>`, not outlined.** It requests Inter first and
falls back to Helvetica/Arial, so on any machine without Inter installed the
lockup renders in a different typeface. Outline it to paths before putting it
anywhere public — a press kit, an OG image, a conference slide — and re-trim
the `viewBox` width to the real ink afterwards. The current width is an
estimate from Inter Bold advance widths, not a measurement.

The mark and badge have no type in them and are safe to use as-is.

## Regenerating the proof

```bash
python ~/.claude/skills/kimono/scripts/verify.py . --out construction-sheet.html
```

Exits non-zero if anything fails. It checks the 48-unit grid, trim, centring,
badge inset, feature count, 16px survival, and XML well-formedness — SVG is
parsed as XML when served as `image/svg+xml`, so a valueless attribute or a BOM
breaks the favicon even though a browser's HTML parser forgives both.

## Alternates

Complete five-file sets, same construction, kept so the choice stays open.
To adopt one, copy its five files over the ones at this level and update the
two inline copies in the website.

| Folder | What it is |
| --- | --- |
| `alt-split-squircle/` | A squircle divided by an S-curve into two interlocking halves. Violet `#7C3AED`. |
| `alt-split-disc/` | The same S-split on a disc. Reads close to a yin-yang, and is otherwise the same idea as the squircle rather than a distinct one. |
| `archive-nexus-n-monogram/` | A letterform **N** built for the name "Nexus". Reference only — it is the wrong letter for Braid. |

Both `alt-split-*` badges shipped with the glyph jammed against the top edge —
a hand-computed `translate(9 0)` that assumed the ink began at the origin and
was square, when it begins at `x=-3` and is 30×25 after scaling. Corrected to
`translate(11.5 11.5)`. That bug reached the live site because `verify.py`
returned exit 0 for anything whose XML parsed, while the geometry checks ran in
the generated page and could not fail the run. Verdicts are computed in Python
now and the exit code reflects them.
