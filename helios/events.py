"""Names that show up in the sign-in and audit log, with a plain-language label."""

EVENT_LABELS = {
    "login_success": "Password accepted",
    "login_failed": "Wrong password",
    "login_denied_disabled": "Sign-in refused because the account is disabled",
    "mfa_success": "Second factor accepted",
    "mfa_failed": "Second factor rejected",
    "sso_session_reused": "Single sign-on. Password was not asked again",
    "token_issued": "A token was issued to an application",
    "saml_issued": "A SAML assertion was issued to an application",
    "logout": "Signed out of the identity provider",
    "joiner": "Joiner. A new person was provisioned",
    "mover": "Mover. Department or group changed",
    "leaver": "Leaver. Account disabled, not deleted",
    "rehire": "Rehire. A previously exited person was activated again",
    "reconcile": "Reconcile. HR was compared with the directory",
    "manual_disable": "An administrator disabled an account by hand",
    "manual_enable": "An administrator enabled an account by hand",
    "role_granted": "A role was granted",
    "role_removed": "A role was removed",
    "mfa_required_on": "MFA turned on for a user",
    "mfa_required_off": "MFA turned off for a user",
    "leave_requested": "Leave requested",
    "leave_approved": "Leave approved",
    "leave_denied": "Leave denied",
    "jit_requested": "Privileged access requested",
    "jit_approved": "Privileged access approved for a short time",
    "jit_denied": "Privileged access denied",
    "jit_expired": "Privileged access expired and was removed",
    "review_certified": "Access review kept a role",
    "review_revoked": "Access review removed privileged access",
    "scim_push": "Account pushed to Payroll through SCIM",
    "lab_reset": "Lab data reset to the starting story",
}


def label_for(event: str) -> str:
    return EVENT_LABELS.get(event, event)
