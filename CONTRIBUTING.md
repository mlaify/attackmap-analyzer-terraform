# Contributing to `attackmap-analyzer-terraform`

Thanks for your interest in improving this AttackMap analyzer plugin. This
document describes how to set up a development environment, run the tests, and
submit changes.

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it. Report unacceptable behavior to
[matthewd@matthewd.xyz](mailto:matthewd@matthewd.xyz).

## Getting started

This is a Python package. Development requires Python 3.11+.

```bash
git clone https://github.com/mlaify/attackmap-analyzer-terraform.git
cd attackmap-analyzer-terraform
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

To exercise this analyzer against the core AttackMap CLI locally, also install
the core package:

```bash
pip install attackmap
# or, for editable dev against a sibling checkout:
# pip install -e ../AttackMap
```

## Running the tests

```bash
pytest
```

## How to contribute

### Reporting bugs

Open a [bug report](https://github.com/mlaify/attackmap-analyzer-terraform/issues/new?template=bug_report.md).
Please include the AttackMap version, this plugin's version, Python version,
OS, reproduction steps, and the smallest input that triggers the issue.

### Suggesting enhancements

Open a [feature request](https://github.com/mlaify/attackmap-analyzer-terraform/issues/new?template=feature_request.md).
For new framework / library coverage, include sample upstream code patterns
the analyzer should detect.

### Submitting changes

1. Fork the repository.
2. Create a topic branch from `main`.
3. Make your change, including tests.
4. Run `pytest` and confirm everything is green.
5. Add a CHANGELOG.md entry under `[Unreleased]` for any user-facing change.
6. Open a pull request using the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

### Adding coverage

Every signal-emitting code path should carry a `file:line` citation, an
evidence-text snippet, and a confidence score. See the AttackMap SDK at
`attackmap.sdk` for the analyzer contract.

## Reporting security issues

Please do **not** open public issues for security vulnerabilities. Email
[matthewd@matthewd.xyz](mailto:matthewd@matthewd.xyz) — see
[SECURITY.md](SECURITY.md) for the full disclosure policy.

## License

By contributing to `attackmap-analyzer-terraform`, you agree that your contributions will be
licensed under the [MIT License](LICENSE).
