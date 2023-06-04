declare module "aponia-v2" {
  interface InternalRequest {
    augmented: true
  }

  interface InternalResponse {
    augmented?: true
  }
}

declare global {
  namespace AponiaAuth {
    interface User {
      augmented?: boolean
    }
  }
}

export {}
