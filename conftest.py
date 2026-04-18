"""Root conftest.

The only thing that must live in a *root* conftest (as opposed to
``tests/conftest.py``) is pyln-testing's plugin registration: pytest
requires ``pytest_plugins`` declarations to appear in a conftest at or
above the rootdir, not in a nested package conftest. Declaring it
nested produces a silent "fixture 'node_factory' not found" error at
collection time.

Everything else — fixtures, helpers, env-driven paths — lives in
``tests/conftest.py`` so test-only wiring stays with the tests.
"""
pytest_plugins = ["pyln.testing.fixtures"]
