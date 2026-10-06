Sigstore bundles written by cosign v3.1.3 `sign-blob --rekor-url` against a local Rekor v1.4.3
(Week 69): the first and second entries of a fresh log, signed with a throwaway key made for the
test. They show the real shape of `tlogEntries[].logIndex` in protobuf JSON: a string, and left
out altogether when it is 0.
