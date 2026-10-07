"""Pytest bootstrap for the PiNOC test suite.

The (otherwise empty) conftest at the repository root makes pytest put the
checkout root on ``sys.path`` when it collects the test suite, so tests can
import the top-level ``pi_noc`` and ``pinoc_agent`` modules exactly the way
the installed service runs them -- whether the suite is invoked as
``pytest tests/`` or ``python -m pytest tests/``.
"""
