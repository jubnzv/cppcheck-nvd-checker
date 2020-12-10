# cppcheck-nvd-checker

Auxiliary script that runs Cppcheck in bughunting mode on NVD CVE datasets.

See [this thread](https://sourceforge.net/p/cppcheck/discussion/development/thread/834110f0e7/) on the Cppcheck forum for the background.

## Usage

You will need Github API token to run this script. Go to settings and [generate](https://github.com/settings/tokens/new) a new one.

Then run this script by the following way:

```bash
GITHUB_TOKEN='fffffff' python3 checker.py
```

This script clones Github repositories affected by NVD CVEs to `/tmp` and runs `cppcheck` in bughunting mode over commits with bug fixes. Please the read source code of the script and the forum discussion before running it.
