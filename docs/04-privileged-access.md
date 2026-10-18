# Project 4 — Privileged access and access reviews

## What this is

`prod-admin` is a powerful role. Nobody has it at the start. A person requests it, a second person approves it, it exists for two minutes, and a worker removes it.

That is just-in-time privileged access.

The other half is the access review. A reviewer looks at current roles and either certifies them ("still correct") or revokes `prod-admin`. The sign-in log records who decided.

Companies often use two hours or eight hours, not two minutes. The lab uses two minutes so you can watch the removal happen.

## Why a company pays for this

Standing admin rights are how a stolen laptop becomes a full outage. Banks, IT service firms, and anyone with a PAM programme want admin to be requested, approved, time-boxed, and written to a log. Access reviews exist because roles accumulate and nobody remembers why.

The products are CyberArk, BeyondTrust, and the privileged-access features in Entra. The certification campaigns are SailPoint. You are not expected to operate those products on day one. You are expected to explain this story without notes.

## When this happens in the job

- A production incident. Someone needs admin for the afternoon, not forever.
- An auditor asks who approved production access last quarter, and when it was removed.
- A review campaign is sitting half finished, and you are chasing reviewers.
- A person still has domain admin from a project that ended last year.

## What to click

Use two windows. One normal, one private. They do not share the identity session, so you can be Kabir and Neha at the same time.

1. Normal window: sign in to Leave Portal as `kabir.das`. Open Privileged access. Request prod-admin with a real reason, for example "investigate a failed payroll deploy".
2. Private window: sign in as `neha.joshi`, complete MFA, open Privileged access, and approve Kabir.
3. Refresh Kabir's window. Read the yellow note. The directory has `prod-admin`. The token does not. This is the snapshot lesson from project 1, attached to a role grant.
4. Stay on the page. The countdown hits zero, the page reloads, and the directory role is gone. The worker did that. Nobody had to remember.
5. Open Access reviews as Neha, or as `iam.admin` in the admin console. Certify one person. If someone still has `prod-admin`, revoke it and then find `review_revoked` in the sign-in log.
6. Try to approve your own request. The lab refuses. A second person has to approve.

The admin console review page explains a limit of the lab: you can revoke only `prod-admin`, so you cannot lock `iam.admin` out. At work, a review can remove ordinary roles too, and break-glass accounts are protected by a separate process.

## What you should be able to say

- Just-in-time means the role has an owner, a reason, an approver, and an end time.
- The worker removes the role when the time ends. The removal is an audit event, `jit_expired`.
- The person's current token does not grow a new role by itself. They need a new sign-in, and that new token is only useful until the grant expires.
- Certify does not change roles. It records that a human looked. Revoke changes the directory.
- Self-approval is refused.
- The log can answer "who approved this, and when did it end?" without opening a database.

## What to ignore

You do not need to read `jit.py`. The privileged page and the sign-in log are the lesson. If you want the order in one place: request, approve, grant role, wait, worker removes role, audit.

## Interview answers

**How would you stop permanent domain admin?**
I would remove standing admin from daily accounts. Production admin would be a request with a reason, approved by a second person, granted for a fixed time, and removed by a job when the time ends. The grant, the use, and the removal would be in the audit log. A quarterly review would catch anything that was granted outside that flow.

**What is the difference between the directory and the token?**
The directory is the live record. The token is a snapshot from sign-in. Granting a role, transferring a department, or disabling an account changes the directory immediately and the token only at the next sign-in. Disabling also does not kill a token that was already issued. That is why privileged grants are short and token lifetimes are short.

**What do you show an auditor?**
The request, the approver, the expiry, the removal event, and the access-review decision. Not a screenshot of a group. The log.
