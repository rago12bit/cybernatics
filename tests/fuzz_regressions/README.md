# Fuzz crash regressions

Empty right now, for an honest reason: see `tests/unit/test_fuzz_regressions.py`'s module docstring.

When a real Atheris run (`tests/fuzz/fuzz_adapter.py`, CI only -- it cannot run on macOS) finds a
crash, libFuzzer writes it as `crash-<hash>` inside the corpus directory you gave it. Copy that file
here, under the adapter's own name:

```
tests/fuzz_regressions/<adapter-name>/crash-<hash>
```

`tests/unit/test_fuzz_regressions.py` discovers every file under here automatically and replays it
through that adapter's `parse()`, asserting it no longer raises. Fix the crash first, then add the
file -- a red test proves the fix, not the other way around.
