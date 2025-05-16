The certificates and private keys in this folder are intended for use by unit tests in the parent folder.

In particular, the `TestClientWithCertificate` unit test uses certificates and private keys from this folder. Note
that this test is expected to run in FIPS mode due to the `requirefips` build tag on the file containing the test.
In FIPS mode, it is not possible to generate insecure keys and their corresponding certificates in test code. Therefore,
the `agent_insecure.key` and `agent_insecure.crt` have been manually generated and stored in this folder. The other keys
and certificates in this folder are all secure (from a FIPS perspective) and could be generated in test code; however,
they are also manually generated for simplifying the test code and since we already have a manually-generated insecure
key and certificate in this folder anyway.
