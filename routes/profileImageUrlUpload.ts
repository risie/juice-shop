/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns/promises'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'svg', 'gif']

function imageExtensionOf (url: string) {
  const extension = url.split('.').slice(-1)[0].toLowerCase()
  return IMAGE_EXTENSIONS.includes(extension) ? extension : 'jpg'
}

// Places only the server can reach: itself, the private network and the
// cloud metadata service on 169.254.169.254.
const internalAddresses = new net.BlockList()
internalAddresses.addSubnet('0.0.0.0', 8)
internalAddresses.addSubnet('127.0.0.0', 8)
internalAddresses.addSubnet('10.0.0.0', 8)
internalAddresses.addSubnet('172.16.0.0', 12)
internalAddresses.addSubnet('192.168.0.0', 16)
internalAddresses.addSubnet('169.254.0.0', 16)
internalAddresses.addAddress('::', 'ipv6')
internalAddresses.addAddress('::1', 'ipv6')
internalAddresses.addSubnet('fc00::', 7, 'ipv6')
internalAddresses.addSubnet('fe80::', 10, 'ipv6')

// The URL text proves nothing: any hostname can point at an internal
// address. So we resolve the name and judge where it really leads.
async function isPublicHttpUrl (rawUrl: unknown) {
  if (typeof rawUrl !== 'string' || !URL.canParse(rawUrl)) return false

  const url = new URL(rawUrl)
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false

  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  const addresses = await dns.lookup(hostname, { all: true }).catch(() => [])
  return addresses.length > 0 && addresses.every(({ address, family }) =>
    !internalAddresses.check(address, family === 6 ? 'ipv6' : 'ipv4'))
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const imageUrl = req.body.imageUrl

    if (imageUrl !== undefined) {
      if (imageUrl.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true

      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
      const userId = loggedInUser.data.id

      if (!(await isPublicHttpUrl(imageUrl))) {
        res.status(400).send('Image URL must be a public http(s) address.')
        return
      }

      try {
        // A public URL may still answer with a redirect that points inside.
        const response = await fetch(imageUrl, { redirect: 'error' })
        if (!response.ok || !response.body) {
          throw new Error('url returned a non-OK status code or an empty body')
        }

        const fileName = `${userId}.${imageExtensionOf(imageUrl)}`
        const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${fileName}`, { flags: 'w' })
        await finished(Readable.fromWeb(response.body as any).pipe(fileStream))

        const user = await UserModel.findByPk(userId)
        await user?.update({ profileImage: `/assets/public/images/uploads/${fileName}` })
      } catch (error) {
        try {
          const user = await UserModel.findByPk(userId)
          await user?.update({ profileImage: imageUrl })
          logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
        } catch (error) {
          next(error)
          return
        }
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
