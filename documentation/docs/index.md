---
id: introduction
title: Aponia Auth
sidebar_position: 0
sidebar_label: Introduction
description: How to use the authentication framework.
slug: /
---

## About Aponia Auth

Aponia Auth is a complete open-source authentication solution for web applications.
Check out the live demos of Aponia Auth in action:

- [SvelteKit](https://aponia-sveltekit-example.vercel.app)
- [Express](https://sveltekit-auth-example.vercel.app)

Continue to our tutorials to see how to use Auth.js for authentication:

- [Setup with OAuth](/getting-started/oauth)

### Batteries included

- Built in support for 60+ popular services (Google, Facebook, Auth0, Apple…)
- Built-in email/password-less/magic link
- Use with any OAuth 2 or OpenID Connect provider
- Use with any username/password store

### Flexible
- Runtime agnostic - run anywhere! Vercel Edge Functions, Node.js, Serverless, etc.
- Use with any modern framework! Next.js, SolidStart, SvelteKit, etc.
- [Bring Your Own Database](/getting-started/databases) - or none! MySQL, Postgres, MSSQL, MongoDB, etc. Choose database sessions or JWT.

_Note: Email sign-in requires a database to store single-use verification tokens._

### Secure by default
- Signed, prefixed, server-only cookies
- Built-in CSRF protection
- Doesn't rely on client-side JavaScript
- JWT with JWS / JWE / JWK.
