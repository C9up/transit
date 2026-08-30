# Test certificate

A throwaway self-signed RSA certificate, standing in for an identity
provider's signing key. It signs nothing outside this test suite and is
committed on purpose: a fixture makes the signature tests deterministic and
free of any external tool.
