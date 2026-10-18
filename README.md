# Helios IAM Lab

A local practice company for the work an IAM engineer actually does: sign-in, joiner-mover-leaver, authorization, and short-lived admin access.

You do not need Docker. You need Python 3.12, which is already what this lab was built with.

```powershell
git clone https://github.com/Shashankia/IAM-labs.git
cd IAM-labs
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Or, if the packages are already installed:

```powershell
python -m helios
```

Leave that window open. Then use one browser.

| System | Address | What it is |
|---|---|---|
| Helios Identity | http://127.0.0.1:8080 | The identity provider and the admin console |
| Leave Portal | http://127.0.0.1:5001 | The business app employees sign in to |
| Payroll | http://127.0.0.1:5002 | A second app, plus the accounts pushed by SCIM |

Lab password for every account: `Helios#2027`

Start as `iam.admin`. That account is you, the IAM engineer.

## What to read

Read `docs/KAISE-PADHO.md` first. It is the click path, in the same language as the questions you asked: what to look at, and what not to study line by line.

| Project | Note | Where you click |
|---|---|---|
| 1. Single sign-on | `docs/01-sso.md` | Leave Portal, the token page, Team Wiki, Payroll |
| 2. Joiner, mover, leaver | `docs/02-joiner-mover-leaver.md` | HR feed, then Users in the admin console |
| 3. Authorization | `docs/03-authorization.md` | Approvals, and `policies/leave.rego` |
| 4. Privileged access | `docs/04-privileged-access.md` | Privileged access, then Access reviews |

`docs/glossary.md` is the short list of words interviews use.

## Accounts

| Username | Job in the story |
|---|---|
| `iam.admin` | You. Admin console, users, applications, sign-in log |
| `aisha.khan` | Engineering employee. Read her token |
| `rahul.mehta` | Engineering manager. Can approve Aisha |
| `sara.fernandes` | Finance manager. Can approve Vikram, not Aisha |
| `vikram.rao` | Finance employee. The person you exit |
| `kabir.das` | Platform engineer. Asks for two minutes of prod-admin |
| `neha.joshi` | HR. MFA is on. Hire, transfer, exit, approve admin access |

## Reset

In the admin console dashboard, use **Reset the lab to the starting story**.

Or stop the lab and run:

```powershell
python -m helios --reset
```

## Tests

```powershell
python -m unittest tests.test_lab -v
```
