# Pushing this work

Copy-paste, top to bottom, from the repository root:

```
P:\Job Applications\Security Archtecture\New framework\threatforge-package\threatforge-threatmodel
```

Nothing here rewrites history or touches `main`. The last step opens a pull
request; merging it is a separate decision you make on GitHub.

---

## 1. Identity (once per machine)

Unset in this repository right now, and the DCO check rejects commits whose
sign-off does not match the author.

```powershell
git config user.name  "R Rajamohan Reddy"
git config user.email "san.rajamohanreddy@gmail.com"
```

Use the same address your GitHub account is verified with, or the DCO bot will
fail the pull request.

---

## 2. Look before you commit

```powershell
git status
```

Expect roughly 45 modified, 32 new, 2 deleted. Two of those deletions are
deliberate:

| Path | Why it goes |
|---|---|
| `TM.md` | Folded into `README.md` and `docs/`; it had a third, conflicting licence statement. |
| `Sample Executive reports/~$…pptx` | A PowerPoint lock file that was committed by accident. |

Confirm the runtime directory is excluded — it holds your SQLite database and a
full clone of a scanned repository, 1.8 MB of state that belongs to your machine
and nobody else's:

```powershell
git check-ignore -v .threatforge
```

That must print a match against `.gitignore:25`. If it prints nothing, stop and
say so.

---

## 3. Branch

```powershell
git switch -c feat/dfd-editor-and-tmt-interop
```

---

## 4. Stage and commit

`-A` picks up the deletions as well as the additions.

```powershell
git add -A
```

The `-s` is not optional. `.github/workflows/dco.yml` fails any pull request
whose commits lack a `Signed-off-by` line.

```powershell
git commit -s -F COMMIT_MSG.txt
```

If you would rather write your own message, `git commit -s` opens an editor and
`COMMIT_MSG.txt` is there as a starting point. Delete it before committing if
you do not want it in the tree.

---

## 5. Push and open a pull request

```powershell
git push -u origin feat/dfd-editor-and-tmt-interop
```

GitHub prints a "create a pull request" URL. Open it, or:

```powershell
gh pr create --fill --base main
```

---

## Before you merge

Three things worth resolving, none of them blocking:

1. **`LICENSE-SECTION.md`** duplicates the licence section already in
   `README.md`. Two copies of a licence statement is how they drift apart.
   Delete it, or fold anything it says that the README does not.

2. **`version = "1.0.0"`** in `pyproject.toml` is a strong claim for software
   with no external users yet. `0.9.0` says the same thing more honestly and
   leaves you 1.0 for when someone else depends on it.

3. **The package name `threatforge`** collides with an unrelated project on
   GitHub. It only bites if you publish to PyPI, but it is cheaper to rename
   before there are installs than after.

---

## If the push is rejected

```
! [rejected]  feat/... -> feat/... (fetch first)
```

Someone pushed to the branch from elsewhere. Do not force:

```powershell
git pull --rebase origin feat/dfd-editor-and-tmt-interop
git push
```

## If the DCO check fails

Add the sign-off to the commits already made:

```powershell
git rebase --signoff origin/main
git push --force-with-lease
```

`--force-with-lease` refuses to overwrite work you have not seen, which plain
`--force` will happily do.
