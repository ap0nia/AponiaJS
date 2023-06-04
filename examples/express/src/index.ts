import 'dotenv/config'

import express from 'express'
import { AponiaAuth } from 'aponia'
import { AponiaSession } from 'aponia/session'
import { GitHub } from 'aponia/providers/github'
import { Google } from 'aponia/providers/google'
import { createAuthMiddleware } from '@aponia/integrations-express'
import cookieParser from 'cookie-parser'

const { 
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET 
} = process.env

const auth = AponiaAuth({
  callbacks: {
    forgot(request) {
    },
  },
  session: AponiaSession({
    secret: 'secret',
    createSession: async (user) => {
      return { accessToken: user, refreshToken: user }
    },
  }),
  providers: [
    GitHub({ 
      clientId: GITHUB_CLIENT_ID ?? '',
      clientSecret: GITHUB_CLIENT_SECRET ?? '',
      onAuth: async (user) => {
        console.log({ user })
      },
    }),
    Google({ 
      clientId: GOOGLE_CLIENT_ID ?? '',
      clientSecret: GOOGLE_CLIENT_SECRET ?? '',
      onAuth: async (user) => {
        console.log({ user })
      },
    }),
  ],
})

const PORT = 3000

async function start() {
  const app = express()

  app.use(cookieParser())

  app.use(createAuthMiddleware(auth))

  app.get('/', (req, res) => {
    res.send('Hello World')
  })

  app.listen(PORT, () => {
    console.log('Server is running')
  })

}

start()
