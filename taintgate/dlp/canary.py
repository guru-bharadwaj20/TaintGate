"""Synthetic canary generation for controlled attack fixtures."""
import secrets


def make_canary():
    return "TAINTGATE_SYNTHETIC_" + secrets.token_hex(16)
