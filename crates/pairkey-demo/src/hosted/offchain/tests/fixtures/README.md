These are public, disposable TLS fixtures for the loopback OIDC integration test.
`test-server.pk8` is deliberately public and must never be used by a real service.
The certificate is valid only for 127.0.0.1 and is signed by the test CA. Normal
workers do not trust that CA. The explicit `test-fixtures` feature exposes a
loopback-only test constructor; it is not an operator configuration option.

The separate RSA ID-token signing fixture comes from pairkey-core's OIDC tests.
Neither fixture represents a configured production provider or a real user login.
