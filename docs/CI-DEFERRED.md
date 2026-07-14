# CI workflows — deferred to a follow-up commit

`build.yml` and `release.yml` (three-platform matrix + tag-triggered
release) were authored during v0.1 but held out of the initial push
because the uploader's `gh` token was missing the `workflow` scope.

To land them:

```bash
gh auth switch --user greenSheep999
gh auth refresh -h github.com -s workflow
```

Then paste in the workflow bodies from
[commit c52547c](https://github.com/greenSheep999/cpa-login-hub/commits/c52547c)
(the original prepared tree, not pushed) or reconstruct them from the
matrix pattern in `docs/DEVELOPMENT.md#releasing`.
