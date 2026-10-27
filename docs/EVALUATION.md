# Detection evaluation and limitations

ShadowTrust v1 uses a deterministic synthetic corpus containing five normal
scenarios and six account-takeover scenarios. Labels belong to scenario
envelopes and never enter the canonical events consumed by detection rules.

## Split discipline

The development split contains three normal and four ATO scenarios used while
building the initial rules. The evaluation split contains two normal and two
ATO scenarios, including an MFA-fatigue holdout variant. The CLI selects the
evaluation split by default so routine reports do not silently mix development
examples into holdout metrics.

Run:

```powershell
cd backend
uv run shadowtrust-evaluate `
  --split evaluation `
  --minimum-recall 1.0 `
  --maximum-false-positive-rate 0.0 `
  --output ..\outputs\evaluation-report.json
```

The current v1 evaluation report contains four scenarios and sixteen timeline
decisions. At risk threshold 70 it reports two true positives, two true
negatives, no false positives, no false negatives, precision 1.0, recall 1.0,
false-positive rate 0.0, and average ATO detection latency 750 seconds.

## What these numbers do not prove

The perfect classification values do not demonstrate production banking
accuracy. The corpus is small, synthetic, deterministic, and authored alongside
the rules. It does not represent population diversity, seasonal behavior,
fraudster adaptation, label noise, missing telemetry, network delay, class
imbalance, or the base rate of real account takeover.

The evaluation split reduces accidental regression risk; it is not a substitute
for a truly independent dataset. If a rule is tuned after inspecting an
evaluation failure, that scenario has effectively become development data and a
new untouched holdout set is required.

## Interpreting the operational metrics

- Precision asks how many alerted scenarios were actually labeled ATO.
- Recall asks how many labeled ATO scenarios were detected.
- False-positive rate measures normal scenarios incorrectly classified as ATO.
- Detection latency starts at the scenario's first attack event and ends at the
  first decision at or above the configured threshold.
- Unnecessary step-up count measures disruptive authentication recommendations
  in normal scenarios.

Future evaluation should add a larger generator with seeded variation, temporal
cross-validation, realistic class imbalance, analyst-label uncertainty,
confidence intervals, and a dataset governed independently from rule authors.
