"""Login provider helpers (vendored from standalone *-login-helper repos).

Each provider module exposes a ``run(req, progress)`` function with a uniform
signature so the server can drive them through a single registry. The contract
is intentionally minimal so it stays compatible with the future
``AccountPoolLoginStrategy`` abstraction we will introduce when this hub is
folded into muxhub's account-pool registry.
"""
