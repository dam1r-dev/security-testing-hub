# Mascot images

The mascot is **Armo**, an armadillo: curled up in his shell when the code is safe, nervous when it is not, alarmed
when it is bad. One separate file per state, no text in the picture, transparent background.

| File | When it is shown | Score |
|---|---|---|
| `mascot-safe.png` | curled up, calm | 80-100 |
| `mascot-warn.png` | nervous, sweating | 50-79 |
| `mascot-danger.png` | alarmed, red eyes | 0-49 |

The current files were cut from the single generated picture (three panels with captions and coloured backgrounds):
the captions painted over and the flat background removed by flood fill from the edges, then scaled to 256x256.

To change the artwork, replace these three files (SVG, PNG or WebP; a different extension also needs the names in
`site/index.html` changed, search for `mascot-`), keep each under 150 KB, then run `npm run mascot` from the repository
root: the HTML report and `security-hub ui` carry an embedded copy, and a test fails when it is out of date.
Square images (256-512 px) work best; they are shown at 132-220 px, so check that the three states stay
distinguishable at 64 px.
