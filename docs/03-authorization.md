# Project 3 — Authorization

## What this is

Sign-in answers "who is this?". Authorization answers "may this person do this thing, to this resource, right now?".

Leave approval is allowed only when all three are true:

1. The person has the `manager` role.
2. The leave belongs to their own department.
3. The clock is a weekday between 09:00 and 18:00 India time.

That is attribute based access control. Role alone is not enough. Department and time are attributes.

The same rule is in `policies/leave.rego`. The Approvals page evaluates it and shows you the reason in a sentence, plus the JSON that was checked.

## Why a company pays for this

Hard-coding `if role == manager` inside every app drifts. One app forgets the department check. Another forgets business hours. A policy file in Git is one rule, reviewed like code, and every app asks the same question.

At 8–10 LPA you will mostly express this as groups and app roles inside Okta or Entra. Some teams also use a policy product, or AWS Verified Permissions, or Open Policy Agent. Being able to read a four-line rule, and explain a denial, is the skill.

## When this happens in the job

- An app owner says "managers should approve only their own team".
- A ticket says "I am a manager and the button does nothing". You check role, department, and any extra condition such as time or country.
- A security review asks you to remove standing broad access and replace it with a narrower rule.
- Someone wants the rule changed. You want that change in a reviewed file, not as a quiet edit inside one application.

## What to click

The starting story has two pending requests: Aisha in Engineering, Vikram in Finance. Today may be outside business hours. The page defaults to a pretend Wednesday so the happy path works. The real clock is printed under it.

1. Sign in as `rahul.mehta`. Open Approvals. Stay on Wednesday 11:00. Aisha is allowed. Vikram is denied, because Rahul is Engineering and Vikram is Finance. Approve Aisha.
2. Switch to Sunday 21:00. Any remaining approval is denied because of the clock. Read the sentence. It tells you which condition failed.
3. Open the JSON once. Find `subject.department`, `resource.department`, and `business_hours`.
4. Sign out everywhere. Sign in as `sara.fernandes`. She can approve Vikram. She cannot approve Aisha.
5. Sign in as `aisha.khan`. She sees the pending items and a denial that says she is not a manager. The button is gone. Seeing the reason matters more than seeing the button.
6. Open `policies/leave.rego`. Read the four lines inside `allow if`. They are the same three conditions, plus the action name.

If you already transferred Aisha to Finance in project 2, Rahul will no longer match her department. Either reset the lab from the admin dashboard before this project, or use the story in that order and expect Rahul to be denied for Aisha after the transfer. Both outcomes are worth saying out loud: "the mover changed the attribute the policy checks."

## What you should be able to say

- RBAC is "managers can approve". ABAC adds "their own department, during business hours".
- The decision uses the token's department and roles. Those are the snapshot from sign-in.
- A denial should say which condition failed. "Access denied" with no reason wastes a day of tickets.
- The policy starts from no. `default allow := false`. Anything not explicitly allowed is refused.
- The JSON on the page is the input. The rego file is the rule. The sentence is the reason a human can read.

## What to ignore

You do not need to learn the Rego language beyond those four lines. You do not need to read `policy.py`. It implements the same three checks so the lab can run without a separate policy server.

## Interview answers

**RBAC versus ABAC?**
RBAC uses the role. ABAC also uses attributes of the person, the resource, and the context. In this lab a manager is not enough. The department has to match, and it has to be business hours. I would rather keep that rule in a reviewed file than copy it into every application.

**A manager says they cannot approve. What do you check?**
Their token: do they actually have the manager role, or is the token from before the role was granted? The resource: is it their department? The context: is there a time, location, or status condition? Then the sign-in log, if the failure is actually authentication and not authorization. Those are different problems.
