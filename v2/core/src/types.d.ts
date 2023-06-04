/**
 * The user that can be __identified__ by a session.
 *
 * @example username, email, profile picture, etc.
 */
export interface User {}

/**
 * The session stored in a JWT, encrypted access token, and then into a cookie.
 * Should be short-lived and contain minimal data needed to identify the user.
 * Refreshed with relevant data from a refresh token.
 *
 * @example session ID, user ID, etc.
 *
 * A session can be the same as the user.
 * Or it may contain a session ID or user ID which is subsequently used to identify the user.
 */
export interface Session extends User {}

/**
 * Data that's used to refresh a session.
 *
 * @example Session ID: Look up the session in the database, extend the expiration data, create tokens.
 * @example User ID: Look up the user in the database, create new tokens with new expiration dates.
 * @example User: Just create new tokens with new expiration dates.
 */
export interface RefreshToken {}
