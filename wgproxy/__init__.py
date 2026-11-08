"""WireGuard to Proxy: turn WireGuard configs into local SOCKS5/HTTP proxies via sing-box."""

__version__ = "1.0.0"

# The sing-box release this code is written and tested against. The Docker image pins it.
SUPPORTED_SING_BOX_SERIES = "1.14."
