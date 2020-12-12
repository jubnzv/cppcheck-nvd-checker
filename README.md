# cppcheck-nvd-checker

Helper scripts to verify Cppcheck bug-hunting mode on NVD CVE datasets.
See [this thread](https://sourceforge.net/p/cppcheck/discussion/development/thread/834110f0e7/) on the forum for background.

## `checker.py`

This script is used to download NVD CVE data and collect additional information about vulnerabilities through Github API.

You will need Github API token to run in. Go to settings and [generate](https://github.com/settings/tokens/new) a new one.

Then run it:

```bash
GITHUB_TOKEN='fffffff' python3 checker.py --format=html > report.html
```

## `equations-printer.py`

Used to generate an HTML report of symbolic equations.

Usage:

```bash
cppcheck main.cpp --bug-hunting --debug --debug-bug-hunting --verbose 2>&1 > data.txt
python3 equations-printer.py main.cpp data.txt > report.html
```
