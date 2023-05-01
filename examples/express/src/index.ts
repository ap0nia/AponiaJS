import 'dotenv/config'

import express from 'express'
import { Aponia, TokenSession, GitHub, Google } from 'aponia'
import cookieParser from 'cookie-parser'


const { 
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET 
} = process.env

type User = { id: number }

type Session = User

type Refresh = User

const auth = Aponia<User, Session, Refresh>({
  session: TokenSession({
    secret: 'secret',
    createSession: async (user) => {
      return { accessToken: user, refreshToken: user }
    },
    handleRefresh: async (tokens) => {
      if (tokens.accessToken) return
      if (!tokens.refreshToken) return
    },
    onInvalidateSession: async (session) => {
      console.log('invalidating session: ', session)
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

const isHeaders = (x: unknown): x is HeadersInit => x != null

const PORT = 3000

async function start() {
  const app = express()

  app.use(cookieParser())

  app.use(async (req, res, next) => {
    const n = Object.entries(req.headers)
    const internalRequest = new Request(req.protocol + '://' + req.get('host') + req.originalUrl, {
      ...req,
      headers: isHeaders(n) ? n : undefined,
    })

    const internalResponse = await auth.handle(internalRequest)

    internalResponse.cookies?.forEach((cookie) => {
      res.cookie(cookie.name, cookie.value, {
        path: '/',
        maxAge: 10000
      })
    })

    if (internalResponse.redirect) {
      return res.redirect(internalResponse.redirect)
    }

    return next()
  })

  app.get('/', (req, res) => {
    res.send('Hello World')
  })

  app.listen(PORT, () => {
    console.log('Server is running')
  })

}

start()
