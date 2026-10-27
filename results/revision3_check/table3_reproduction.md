# Revision 3 (step 8): Table III configurations reproduce exactly

Reproduce: `python -m experiments.revision3_check`. Full score() output vs `results/<day>/results.json`
(unrounded). In the paper the main grid is Table II.

| Day | Configuration | identical |
|---|---|---|
| friday | count / fixed | yes |
| friday | count / adaptive | yes |
| friday | behaviour / fixed | yes |
| friday | behaviour / adaptive | yes |
| friday | all / fixed | yes |
| friday | all / adaptive | yes |
| friday | all / adaptive, no freeze | yes |
| wednesday | count / fixed | yes |
| wednesday | count / adaptive | yes |
| wednesday | behaviour / fixed | yes |
| wednesday | behaviour / adaptive | yes |
| wednesday | all / fixed | yes |
| wednesday | all / adaptive | yes |
| wednesday | all / adaptive, no freeze | yes |

All identical: **yes** (wall 100 s, 8 processes).
