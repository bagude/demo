# Live harness check

Written under packet 5097e5a0b844 with the repaired kernel armed, to exercise
the allow path end-to-end: platform-absolute tool path → workspace rebinding →
scope check → obligation opened → commit gate → discharge.

Second pass, after the run-identity fix: this edit's events should carry the
session id from the hook payload rather than a per-invocation `unbound-$PPID`.
