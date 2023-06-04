# Aponia Auth

## Concepts

### User
- Literally the user information.

### Session
- The information stored in an access token.
- Used to get a user. Examples...
  - The user itself, i.e. token-based approach.
  - Just the user's session ID, i.e. database-based approach.

### Access Token
- A JWT, encrypted string that's stored in a cookie

## Refresh Token
- A JWT, encrypted string that's used to refresh a user's session.

## Auth Approaches

### Token-Based
- Store the user in the access token.
- To identify the user of a request, just decode the access token cookie.
- To renew a session, use the data in the refresh token to generate new tokens.

### Database-Based
- Store only the user's session ID in the access token.
- The database should have a corresponding session with an expiration date
- To identify the user of a request, decode the access token cookie and look up the session ID in a database.
- To renew a session,
  use the data in the refresh token to modify the database (i.e. changing the session's expiration date or just creating a new one)
  and then generate tokens

## Ideas for Refresh Tokens
Note: Because the refresh token is JWT + encrypted, a successful decode means that it was initially created by you.

### The user or user ID.
After successfully decoding the refresh token and getting some user info, you can use that info to generate another access token.
And you'd probably use the same refresh token data (i.e. same user ID or user info) with a new expiration date.

### The session ID.
You can also store the session ID in a refresh token (i.e. both access and refresh tokens might have the same data).
The main difference between the tokens in this case is that the access token has a shorter lifespan.
The session ID can be decoded from the refresh token, and the corresponding session found in the database.
Then the sesion can be extended or a new session can be created.
Take the resultant session's ID and put them back into tokens.

## Life-Cycle
1. Initialize the Auth class
  - It can generally handle static auth routes.
2. An incoming `Request` object is converted to an `InternalRequest`
3. If the request is for a static auth URL, then the Auth class handles it directly and returns.
  - e.g. `/auth/logout`, `/auth/forgot`, `/auth/reset` etc.
  - They're considered static because those routes aren't inherently associated with a provider.
  - i.e. Google doesn't send you a reset-password link for your own website...that's your job.
4. If the request is for a provider, then the Auth class delegates it to the provider, but doesn't return yet!
  - Internally, each provider stores a map of the routes it will handle, which is configurable!
  - e.g. `/auth/login/github`, `/auth/callback/github`
  - The base Auth class simply reads these routes, and then creates a `Map` that connects the auth route string with the provider class.
  - Then when a match is found, the Auth class will invoke the proper method on the provider.
  - i.e. If `/auth/login/github` matched with the request URL, then the `GitHub` provider was found in the Map and its `login` method will be invoked.
5. If a user was created during the provider request, i.e. after logging in with OAuth,
   then the session managers's `createSession` handler is invoked with the user.
6. Finally the handling is done.

## Objects / Methods

### User
A user represents the identified user for the current request.
Generally won't be defined, and lazily evaluated with `getUser`.

### `getUser`
Checks the request to see if `user` is defined. If not, then...
1. Decode the access token from cookies
2. Invoke the session manager's `getUserFromSession`. Remember, the `user` and `session` aren't always the same!
3. Save the user into the request.
4. Return the user.

