<!-- tracelane:classification: PUBLIC -->

# Tracelane eval gate — GitHub Action

Fail a pull request when eval quality falls below a threshold you set.

```yaml
- uses: tracelane/tracelane/.github/actions/eval-gate@main
  with:
    prompt: support-triage
    suite-file: .tracelane/triage.eval.json
    dataset: golden-cases
    threshold: "0.9"        # a FRACTION — 0.9 is 90%. `90` is rejected.
    token: ${{ secrets.TRACELANE_API_KEY }}
```

The prompt version is resolved from `env` (default `staging`), so no UUID lives
in the workflow file.

## The suite file

```json
{
  "assertions": [
    { "kind": "contains", "value": "refund" },
    { "kind": "json_schema", "schema": { "required": ["decision"] } }
  ]
}
```

**`assertions` must be non-empty.** The gateway's scorer starts from
"everything passed" and never enters the loop when the list is empty, so a run
with no assertions reports 100% and the gate is green on the day the prompt
breaks. The CLI refuses it with exit `2` before spending a provider call.

Omit `dataset` and put a `cases` array in the same file to run inline cases
instead. A frozen dataset is the reproducible option — an inline list is only as
stable as the file.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | pass rate **at or above** the threshold — a tie passes |
| `1` | **below the floor** — the mean score is below `threshold`. The only code that means "your prompt did not meet the bar" |
| `2` | bad invocation — a missing flag, an unreadable suite file, `--threshold 90` |
| `3` | **could not evaluate** — too many cases errored, run unfinished, gateway refused |

**`3` fails the job deliberately, and there is no input that turns it into `0`.**
"The gate could not check" and "the gate checked and was satisfied" are
different facts, and a CI step that goes green on the first silently disarms the
gate for the whole repo.

## The comparison, stated

- **Direction** — higher is better, and `threshold` is a **floor**:
  `threshold: "0.8"` means "fail if the mean score is below 0.8".
- **Ties pass.** `score == threshold` exits 0. A gate that fails on exactly the
  number you set is a gate nobody can configure.
- **It thresholds the mean SCORE, not the pass rate.** For `contains`,
  `exact_match` and `json_schema` a case scores exactly `1.0` or `0.0`, so the
  mean *is* the pass rate and nothing changes. For an LLM judge the score is
  continuous, and there the two differ: a judge scoring 0.68 against a 0.70 rule
  and one scoring 0.02 are the same "failed" and very different results.
- **Errored cases are excluded from the mean**, not scored as zero. One provider
  `429` in a 20-case run is not a 5% below-the-floor result, and a gate that goes red on a
  `429` gets deleted in a week. They are bounded separately by `max-error-rate`
  (default `0.10`); above it the verdict is `3`, and a run where *every* case
  errored is `3` — never a vacuous pass.

## What this gate does NOT do

**This gate asserts a FLOOR on a single run. It does not detect below-the-floor results.**
There is no baseline, no history and no comparison — the same shape as a
coverage threshold, which nobody considers broken for lacking a previous run.
A run scoring 0.9 today and 0.85 tomorrow clears a 0.8 floor both times, and
calling the second result "no below-the-floor result" would be a claim nothing checked.
Comparing a run against an earlier one is a real gap and is filed, not built:
what counts as the baseline is a design decision, not a flag.

## Requirements

A `dataset` must have a **frozen snapshot** — a run against a live item list
could not be reproduced, which is the only reason to run one. Freeze with
`POST /v1/datasets/{id}/snapshots`; an unfrozen dataset is refused with exit `2`
and a message saying so.

The token needs **both** the `read` and `admin` scopes. Scopes are a flat set
with no hierarchy: `admin` starts a run, `read` polls it, and `admin` does not
imply `read`.
