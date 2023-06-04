import { handle, Callback } from 'aponia-v2'

const callback: Callback = async (req) => {
  req.augmented
  return { 
    user: {
    } 
  }
}

handle(callback)

import { google } from 'aponia-v2/providers/google'

google()
