# Words you will hear

| Word | Meaning in this lab, and at work |
|---|---|
| Identity provider (IdP) | The system that checks the password and issues the proof. Here it is Helios Identity. At work it is Okta, Entra ID, or Keycloak. |
| Application / service provider | The app the person actually wanted. Leave Portal and Payroll. |
| OIDC | The modern sign-in protocol. The app receives a signed token. |
| OAuth | The token-issuing family OIDC is built on. Interviews mix the two names. OIDC is the identity part. |
| SAML | The older sign-in protocol. The app receives an XML assertion instead of a token. Same facts, different envelope. |
| PKCE | A proof that the app which started the sign-in is the app exchanging the code. Stops a stolen code from being reused by someone else. |
| Claim | One fact inside a token: name, department, expiry, roles. |
| Issuer (`iss`) | The exact address of the identity provider that minted the token. |
| Audience (`aud`) | The app the token was minted for. Leave Portal must reject a Payroll token. |
| Scope | What the app asked to receive. `openid` means "this is an identity sign-in". |
| MFA | A second proof after the password. Here it is a 6-digit code that changes every 30 seconds. |
| Group | Where the person sits. In this lab the group matches the department. |
| Role | What the person may do. `manager` can approve. `employee` can request. |
| RBAC | Role based access. "Managers can approve." |
| ABAC | Attribute based access. "Managers can approve their own department, on a weekday." Project 3 is this. |
| SCIM | The standard way an identity system pushes accounts into an application. Create, update, and set `active` to false. |
| Joiner | A new hire. Create the account, put them in a group, push the app account. |
| Mover | A transfer. Change the group. Do not wipe their other roles. |
| Leaver | An exit. Disable the account. Do not delete the history. |
| Reconcile | Compare HR with the directory and fix the drift. This is the nightly safety net. |
| Provisioning | Creating or updating an account in a target system. |
| JIT | Just in time. Admin access is granted for a short window, then removed. |
| PAM | Privileged access management. The product family (CyberArk, BeyondTrust) that does what project 4 demonstrates. |
| Access review / certification | A person looks at who still has a role and keeps it or removes it. |
| Standing access | A role with no expiry. The risky kind of admin. |
| Least privilege | Give the smallest role that still lets the person do the job. |
| Token lifetime | How long the snapshot stays valid. After that, the app must send the person through sign-in again. |
| Redirect URI | The exact address the identity provider is allowed to send the user back to. A typo here is the most common SSO ticket. |
