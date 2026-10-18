# Project 2 — Joiner, mover, leaver

## What this is

HR is the source of truth for who works here. The identity provider is the source of truth for who can sign in. Payroll keeps its own copy of the account, pushed by SCIM.

Three events:

- Joiner. Someone is hired. Create the login, put them in the department group, give them the employee role, push Payroll.
- Mover. Someone changes department. Change the group. Leave their other roles alone. Update Payroll.
- Leaver. Someone exits. Disable the login. Mark Payroll inactive. Do not delete the account.

Reconcile is the safety net. It compares every HR row with the directory and repairs drift.

## Why a company pays for this

The dangerous failure is a person who has left and can still sign in on Monday. The expensive failure is a new hire who sits for two days because nobody created their accounts by hand. A worker tied to HR does both, and the audit log shows that it happened.

## When this happens in the job

This is most of an IAM analyst or engineer week at a service company, a bank, or a GCC.

- A joiner ticket, or a Workday event, that did not create the account.
- A mover whose old department group is still there, so they can still see the old team's app.
- A leaver who is disabled in HR and still active in the directory.
- A monthly reconcile report of the mismatches.
- A broken SCIM connector, where the directory is right and the target app is wrong.

The tools are SailPoint, Entra provisioning, or an Okta workflow. The order of steps is what you practised here. The buttons live in the product.

## What to click

Sign in as `neha.joshi`. She has MFA, so this also revises project 1. Open **HR feed**.

Look at the table before you click anything. Three columns: HR, Directory, Payroll. They match at the start. That match is the healthy state.

Then, in order:

1. Hire Meera Iyer. The form is already filled in. After it succeeds, Meera is active in all three columns. She can sign in as `meera.iyer` with the lab password.
2. Transfer Aisha Khan to Finance. Her group changes. Her employee role stays.
3. Exit Vikram Rao. HR says Left. The directory says Disabled. Payroll says Inactive. The row is still there.

Now sign out everywhere and open the admin console as `iam.admin`.

- Users: Vikram is disabled, not missing.
- Groups: Aisha is under Finance.
- Sign-in log: `joiner`, `mover`, `leaver`.

Two experiments that are the actual job:

**Disable by hand, then reconcile.** As `iam.admin`, open Aisha and click Disable. Try to sign in as Aisha. The message says the account is disabled, which is different from a wrong password. Then as Neha, click **Run reconcile**. Aisha comes back, because HR still says she works here. The console is not the source of truth. HR is.

**Exit, then reconcile.** Vikram stays disabled. Reconcile will not resurrect a leaver. That is the difference between a manual disable and an HR exit.

Open Payroll → Provisioned accounts. Read the table. Open one JSON payload only after the table makes sense. Look for `userName`, `active`, and `department` inside the enterprise extension.

## What you should be able to say

- The worker runs at the moment of the HR event. Reconcile is the nightly comparison, in case an event was missed.
- A joiner creates the identity account and the downstream account. The password in this lab is shared so you can sign in. At work the person sets their own, or gets a one-time invite.
- A mover changes group and department. It does not remove `manager` from a manager.
- A leaver is disabled, not deleted. Audit and history remain.
- A token issued before the exit keeps working until `exp`. Disable is not instant for sessions that already exist. Short token lifetimes are how you shrink that window.
- SCIM `active: false` is the application's copy of "do not let them in".
- The SCIM call uses a service credential, the bearer token on the Payroll page. That is not a person's password. At work it lives in a vault.
- `iam.admin` is not in HR. Break-glass admin accounts are often created in the directory, not hired through the feed.

## What to ignore

You do not need to read the SCIM route code. You need to recognise the JSON shape and the three columns.

If an interviewer asks for the steps, open `helios/jml.py` and read the comment at the top. Joiner, mover, leaver, five lines each. Stop there.

## Interview answers

**How do you handle a leaver?**
HR marks them inactive. The worker disables the directory account and sets the downstream account to inactive through SCIM. I do not delete the account, because the audit trail has to remain. I also know an already issued token lives until it expires, so the token lifetime has to be short, and the sign-in log should show the disable.

**What is the difference between a group and a role?**
The group is where they sit, here the department. The role is what they may do, such as manager or employee. A transfer changes the group. It should not silently remove a manager role.

**What do you check when a new hire cannot log in?**
HR row present and active, directory account present and enabled, group assigned, downstream app account present and active, and the sign-in log for a failed password or a disabled account. Those are different failures and they have different fixes.
