import '@aponia/sveltekit'

declare global {
  namespace App {
    interface Locals {
      getUser: () => Promise<Aponia.User | null>
    }
  }

  namespace Aponia {
    interface User {
      name: string
    }
  }
}

export {}
