import { AponiaSession } from 'aponia/session'
import { Google } from 'aponia/providers/google'
import { GitHub } from 'aponia/providers/github'

console.log(Google({ clientId: '', clientSecret: '' }))
console.log(GitHub({ clientId: 'githubid', clientSecret: 'githubsecret' }))

let l: Aponia.User = { id: 1 }

const s = AponiaSession({
  secret: 'secret!!',
  createSession(user) {
  },
})

