### Kerberos Conditional plugin

This Keycloak extension is inspired by the [KeycloakConditionalSpnegoAuthenticator](https://github.com/slominskir/KeycloakConditionalSpnegoAuthenticator).

I has two main functions:

- allowing skipping of Kerberos authentication based on networks or cookies (or both).
- allowing limiting kerberos to IP ranges

This addresses a common compaint about allowing users to logout and log in again with another user account and/or with username/password

It uses a cookie to skip another kerberos login, when configured to do that.

### Installation

Build it with Maven, copy the jar to the `/opt/keycloak/providers/` directory.

I can provide the jar as a release if people starts asking for it.

<img width="556" alt="Screenshot 2024-09-12 at 08 41 03" src="https://github.com/user-attachments/assets/0d9cfc17-96df-4d4c-9cca-e10b8ebd68e4">
