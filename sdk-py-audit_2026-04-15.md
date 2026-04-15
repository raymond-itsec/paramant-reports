## Paramant Python SDK findings
**Date:** 2026-04-15
**Prepared by:** R. Zwarts
**Function:** Python code audit
**Classification:** Responible disclosed on April 15th 2026

For the Python SDK in sdk-py/pyproject.toml (line 25):

On Python 3.10+: probably no, not in a normal fresh install today.
On Python 3.9: yes, it can resolve to a currently vulnerable version.
Why:

The package declares loose minimums, not pinned versions:

requests>=2.28
cryptography>=41
websockets>=12
at sdk-py/pyproject.toml (line 25)
As of 2026-04-15, current PyPI metadata shows:

requests latest is 2.33.1, no current PyPI vulnerability listed, but it requires Python >=3.10: requests latest JSON
websockets latest is 16.0, no current PyPI vulnerability listed, and it requires Python >=3.10: websockets latest JSON
cryptography latest is 46.0.7, no current PyPI vulnerability listed: cryptography latest JSON
The important catch is Python 3.9. Because the project still claims requires-python = ">=3.9" at sdk-py/pyproject.toml (line 11), pip on Python 3.9 cannot take requests 2.33.x. It backtracks to requests 2.32.5, and PyPI currently flags that release with CVE-2026-25645, fixed in 2.33.0: requests 2.32.5 JSON

So the cleanest direct answer is: a fresh install on Python 3.10+ is likely fine today, but a fresh install on Python 3.9 will currently pull a PyPI-flagged vulnerable requests release. That means the codebase is still not “safe by construction” for Python installs.

One extra nuance:

If you install the dev extras on Python 3.9, pytest also backtracks to 8.4.2, which PyPI currently flags with CVE-2025-71176, fixed in 9.0.3: pytest 8.4.2 JSON
That does not affect a normal runtime install unless you install the dev dependencies too.
Summary:

Normal install on Python 3.10+: likely not vulnerable today
Normal install on Python 3.9: yes, vulnerable requests can be installed
Dev install on Python 3.9: also vulnerable pytest can be installed
