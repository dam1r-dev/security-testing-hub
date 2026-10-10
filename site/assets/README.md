# Mascot images

The mascot is **Armo**, an armadillo: curled up in his shell when the code is safe, nervous when it is not, alarmed
when it is bad. Use one separate file per state, with no text baked into the picture and a transparent background.

The site shows one image per security state. Replace these three files with the final artwork (same file names;
SVG or PNG — if you use PNG, change the extension in `site/index.html`, search for `mascot-`):

| File | When it is shown | Score |
|---|---|---|
| `mascot-safe.svg` | calm / happy | 80-100 |
| `mascot-warn.svg` | uneasy | 50-79 |
| `mascot-danger.svg` | alarmed / panic | 0-49 |

The current files are placeholder sketches of a shield. Square images (e.g. 512x512, transparent background) work best;
they are shown at up to 220 px, so check that the three states stay distinguishable at 64 px.
