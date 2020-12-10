# cppcheck-nvd-checker

An auxiliary script that runs Cppcheck in bughunting mode on NVD CVE datasets.

See [this thread](https://sourceforge.net/p/cppcheck/discussion/development/thread/834110f0e7/) on the Cppcheck forum for the background.

## Usage

You will need Github API token to run this script. Go to settings and [generate](https://github.com/settings/tokens/new) a new one.

Then run the script:

```bash
GITHUB_TOKEN='fffffff' python3 checker.py
```

Please read the source code of the script and the forum discussion before running it.
