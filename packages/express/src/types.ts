import 'aponia'

declare global {
  namespace Express {
    export interface Request {
      /**
       * Property to save the user in. 
       * Undefined if {@link getUser} has not been called.
       * Null if the user is not logged in, i.e. {@link getUser} failed.
       * Otherwise, defined with the user object.
       */
      user?: Aponia.User | null

      /**
       * Either retrieves the saved user or decodes tokens.
       */
      getUser: () => Promise<Aponia.User | null>

      /**
       * Generated internal response will be saved her when debugging.
       */
      aponiaAuthResponse?: Aponia.InternalResponse

    }
  }
  namespace Aponia {
    interface InternalRequest {
      expressRequest: Express.Request
    }
  }

}

export {}
