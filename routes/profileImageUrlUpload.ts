/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// Destinations the server must never be talked into fetching: its own loopback,
// private LAN ranges, and link-local — which includes the cloud metadata
// service at 169.254.169.254.
function isInternalAddress (ip: string): boolean {
  if (net.isIP(ip) === 0) return true // couldn't parse it → don't risk it
  if (ip.startsWith('127.') || ip === '::1') return true // loopback
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true // private
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true // 172.16–31 private
  if (ip.startsWith('169.254.') || ip === '0.0.0.0') return true // link-local / unspecified
  if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80')) return true // IPv6 ULA / link-local
  return false
}

// Only public http(s) URLs may be fetched. We resolve the host ourselves and
// vet the address it actually points at, so a hostname can't smuggle us to an
// internal target.
async function assertPublicHttpUrl (raw: string): Promise<void> {
  const url = new URL(raw) // throws on a malformed / scheme-less URL
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http(s) URLs are allowed')
  }
  const { address } = await dns.lookup(url.hostname)
  if (isInternalAddress(address)) {
    throw new Error('Refusing to fetch an internal address')
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          await assertPublicHttpUrl(url) // reject internal targets before fetching
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
