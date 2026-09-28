# Security notice

This repository is a **research prototype**, not a production authorization system.

It intentionally simplifies PKIX validation, policy distribution, revocation, persistence, audit storage, and network isolation so that specific authorization trade-offs can be measured in a small experiment.

Do not reuse generated keys or certificates outside the local experiment. Private keys are ignored by Git and should never be committed.

If you find a security issue in the prototype itself, open an issue describing the behavior without including credentials, private keys, or sensitive system data.
