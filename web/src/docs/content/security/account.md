---
title: Account security
description: Password sign-in without sending the password, two-factor authentication, device approval and recovery.
---

## Sign-in with OPAQUE

Termoso signs you in with **OPAQUE**, a password-authenticated key exchange. The server stores a per-user record and checks a cryptographic proof; your password is never sent — not in plain text, not hashed. The same exchange produces the key that unwraps your account keys on the device.

## Two-factor authentication

Under **Security** in the cabinet or the app, add one or more second factors:

- authenticator app (TOTP);
- passkeys and security keys (WebAuthn / FIDO2), including from Android over USB or NFC;
- e-mail codes;
- backup codes for emergencies.

## New devices

A new device has to be approved from a device that is already signed in, or through the link the server e-mails you. The list of devices and their last activity is under **Devices**; revoking one signs it out immediately.

## Recovery key

At sign-up you get a 24-word recovery key. It is the only way back in if you forget your password — the server cannot reset it for you. Keep it offline.

## Single sign-on

The hosted cloud offers **Sign in with GitHub**; self-hosted servers can add any OpenID Connect or SAML 2.0 provider. With SAML, signing out of Termoso can also end the identity-provider session (Single Logout), and a logout started at the identity provider signs you out of Termoso on every device that session signed in. SSO proves who owns the e-mail address; your vault password and recovery key remain the only ways to unwrap key material, so the identity provider cannot read vaults.

**Corporate domains.** A team whose policy says *Sign in only through SSO* and lists e-mail domains owns those domains on the server: nobody can create a password account on them or sign in with a password — not even someone who is not (yet) a member — the server answers `sso_required` and the apps offer the team's provider instead. The team's owners and the server's bootstrap administrators are exempt so a misconfigured IdP can never lock everyone out.

### Connected accounts

**Security → Connected accounts** lists the providers linked to your account. *Connect* starts the provider's sign-in and links the identity it returns; *Disconnect* asks you to re-enter your password first. If you sign in with a provider whose e-mail already belongs to your account, you are asked for your password and the identity is linked once it checks out — no second account is created. An identity that is already linked to another account cannot be connected to yours.

### Sessions

A device holds one session. Signing in again on the same device replaces the previous session, so **Devices** never shows duplicates for one browser or phone; signing out revokes only the current device.
