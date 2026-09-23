"""Reproducible property-test defaults without downloading model assets."""

import os

from hypothesis import settings

settings.register_profile("ci", max_examples=100, derandomize=True, database=None, deadline=None)
settings.register_profile("local", max_examples=200, deadline=None)
settings.load_profile(os.environ.get("TAINTGATE_HYPOTHESIS_PROFILE", "ci"))
