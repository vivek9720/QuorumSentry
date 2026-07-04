# Submission Notes

This project follows the required layout:

- `.clusterfuzzlite/build.sh` builds all JVM harnesses.
- `fuzz/` contains five connected harnesses.
- `fuzz/corpus/` contains per-harness seeds.
- `fuzz/dictionary.txt` contains tokens for the parsers and DSL.

External PoC files are intentionally stored outside this repository in a sibling PoC folder.
