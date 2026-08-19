# Fixtures

Small projects used by the auditor's tests. They are **not** examples to copy.

- `vulnerable-react-native/` — contains deliberate, documented weaknesses. Every file here exists to
  make a rule fire. Nothing in it is a real credential: the values are syntactically valid and
  functionally useless.
- `secure-react-native/` — the same application shapes written safely. Its job is to catch false
  positives, which is the harder half of a scanner.

The auditor's own severity engine downgrades findings under `fixtures/` by two levels, so scanning
this repository does not drown in the problems it was told to contain.
