<!--
Thanks for opening a pull request! A few things to check before submitting:
1. Tests run cleanly: `pytest`
2. CHANGELOG.md has an entry under [Unreleased] for any user-facing change
3. New signals carry file:line citation + evidence text + confidence
-->

## Summary

<!-- One or two sentences describing the change. -->

## Motivation

<!-- Why is this change needed? Link to any related issue. -->

Fixes # <!-- (issue number if applicable) -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New framework / library coverage
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] Documentation update
- [ ] CI / tooling / hygiene

## Testing

- [ ] `pytest` passes locally
- [ ] Added or updated tests covering the change
- [ ] Verified the analyzer is discovered by `attackmap modules`

## CHANGELOG

- [ ] Added an entry to `CHANGELOG.md` under `[Unreleased]`

## Checklist

- [ ] My code follows the existing style in the repo
- [ ] I have performed a self-review of my own code
- [ ] New signals carry `file:line`, evidence text, and confidence
- [ ] No secrets, API keys, or PII included in this diff
