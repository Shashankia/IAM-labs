# Project 1 — Single sign-on

## What this is

Leave Portal and Payroll do not store passwords. Helios Identity does. A person proves who they are once, and each application receives its own signed proof.

You will see two envelopes for that proof:

- OIDC, on Leave Portal and Payroll. The proof is a token with claims.
- SAML, on Team Wiki. The proof is an XML assertion. The facts inside it are the same.

## Why a company pays for this

People stop keeping a different password in every app. The company can turn on MFA in one place. When someone leaves, you disable one account instead of hunting through twenty apps. The sign-in log is in one place when a ticket says "I cannot log in".

## When this happens in the job

This is the daily app-onboarding ticket.

1. A team wants their app to use company login.
2. You register the app: protocol (OIDC or SAML), client id, and the exact reply address.
3. You map groups or roles into what the app expects.
4. You turn on MFA if the app is sensitive.
5. You test with a pilot user and read the sign-in log if it fails.

In this lab the apps are already registered. Open **Applications** in the admin console and read the three cards. That screen is the job. At work the same screen is an Okta app integration or an Entra app registration.

## What to click

1. Sign in to Leave Portal as `aisha.khan`. Watch the browser go to the blue Helios Identity page. That jump is the whole idea.
2. On Home, read the five steps and the table "token versus the directory".
3. Open **Your token**. Read the table. Then look at the three pieces: header, payload, signature.
4. In the same browser, open Payroll and sign in. Stop on the blue page that says you are already signed in. Read it. Then continue.
5. Back in Leave Portal, open **Team Wiki (SAML)**. Read NameID, issuer, audience, and expiry before you open the XML.
6. Click **Log out of Leave Portal only**, then sign in again. The password is skipped, because the identity provider session is still there.
7. Click **Log out everywhere**, then sign in again. The password is required.

Also sign in once as `neha.joshi` and type the 6-digit code. That is MFA. The lab prints the code because you may not have an authenticator app. A company would not print it. The code still rotates every 30 seconds, which is the real behaviour.

## What you should be able to say

- The application never saw the password. The identity provider did.
- `iss` is who minted the token. The app must accept only that issuer.
- `aud` is which app the token is for. A Leave Portal token is not a Payroll token.
- `exp` is when the snapshot dies. This lab uses 10 minutes.
- `groups` and `roles` are copied at sign-in. They do not update themselves.
- The second app skipped the password because the browser still had a session cookie at the identity provider.
- PKCE is the check that the app which started the sign-in is the same app exchanging the code. You do not calculate it by hand. You need to know why it exists: so a stolen code is useless without the secret the app held back.
- SAML's NameID is the same idea as `preferred_username`. Audience is the same idea as `aud`. `NotOnOrAfter` is the same idea as `exp`.
- The SAML request was compressed in the address bar. The response came back as a POST, base64, not compressed.
- This lab does not sign the SAML assertion. A company IdP would, and the app would check the signature, the audience, and the expiry before trusting the name.

## The usual ticket

`redirect_uri mismatch`. The app asked to return to an address that is not the one you registered. Open Applications and compare the reply address character by character. A trailing slash is enough to break it.

The second usual ticket: the person signed in, but the app says they have no role. The token was issued before the role was granted. They must sign in again. Home shows this as "token versus directory".

## What to ignore

The HTML, the CSS, and `store.py`. If someone asks what the application does during sign-in, open `helios/oidc_client.py` and read the five lines at the top. That is the whole file you need.

## Interview answers

**Walk me through a login.**
The app sends the browser to the identity provider with a client id, a redirect address, a state, and a PKCE challenge. The person enters the password there. The identity provider sends back a one-time code. The app exchanges that code, with the PKCE verifier, for a signed token. The app checks the signature, the issuer, the audience, and the expiry, then reads the claims.

**What is the difference between SSO and a token?**
SSO is the session at the identity provider. It is why the second app does not ask for the password. The token is the snapshot one app received. Logging out of the app does not always log you out of the identity provider. Logging out of the identity provider forces the next app to ask again.

**OIDC or SAML?**
Whichever the application supports. New apps are usually OIDC. Older enterprise apps are often SAML. The identity facts are the same. I have read both a token and an assertion.
