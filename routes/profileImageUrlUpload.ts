/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import { lookup as dnsLookup, type LookupAddress, type LookupAllOptions, type LookupOneOptions } from 'node:dns'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import { fetch, Agent } from 'undici'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// ---------------------------------------------------------------------------
// SSRF protection for "set profile picture from a URL"  (CWE-918 / Proactive
// Control C10 — Stop Server-Side Request Forgery).
//
// This feature makes the SERVER fetch a URL the user typed. Unchecked, a user
// can aim it at things only the server can reach: its own loopback, the private
// network, or the cloud metadata service at 169.254.169.254 that hands out the
// server's credentials. The attacker borrows the server's position inside the
// network.
//
// You cannot fix this by inspecting the URL *string*. A normal-looking name
// (images.example.com) can resolve to an internal IP, and the answer can even
// change between the moment you check it and the moment you connect — that's
// DNS rebinding. So, per the OWASP SSRF Prevention Cheat Sheet, the real
// defence is:
//   1. Allow only http(s) URLs (reject file:, gopher:, ...).
//   2. Resolve the host and refuse internal addresses — doing that resolution
//      AT CONNECT TIME and connecting to the exact address we checked, so there
//      is no gap for rebinding, and checking EVERY address the name resolves to.
//   3. Do not follow redirects — a public URL can 302 straight back inside.
//
// Honest caveat: this is a deny-list of "internal" ranges, and deny-lists are
// bypass-prone (the cheat sheet prefers an ALLOW-list of known image hosts). We
// use one only because this feature accepts arbitrary image URLs by design. A
// real app that needs just a few image CDNs should allow-list those instead —
// that's the Level-2 version of this fix.
// ---------------------------------------------------------------------------

// An IPv4 address can hide inside an IPv6 one: ::ffff:169.254.169.254 (or its
// hex form ::ffff:a9fe:a9fe) is really 169.254.169.254. Judge it as the IPv4 it
// maps to, or the metadata address sails straight through the checks below.
function normalizeIp (ip: string): string {
  const mapped = /^::ffff:(.+)$/i.exec(ip)
  if (mapped == null) return ip
  if (net.isIPv4(mapped[1])) return mapped[1]
  const hex = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(mapped[1])
  if (hex != null) {
    const hi = parseInt(hex[1], 16)
    const lo = parseInt(hex[2], 16)
    return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`
  }
  return ip
}

// Is this resolved address somewhere the server must never be sent?
function isInternalAddress (raw: string): boolean {
  const ip = normalizeIp(raw)
  if (net.isIP(ip) === 0) return true                                 // can't parse it → don't risk it
  if (ip.startsWith('127.') || ip === '::1') return true              // loopback
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true  // private (RFC 1918)
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true              // 172.16–31 private (RFC 1918)
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true // 100.64/10 carrier-grade NAT
  if (ip.startsWith('169.254.')) return true                          // link-local → cloud metadata!
  if (ip === '0.0.0.0' || ip === '255.255.255.255') return true       // unspecified / broadcast
  if (/^(22[4-9]|23\d)\./.test(ip)) return true                       // 224–239 multicast
  if (ip.startsWith('fc') || ip.startsWith('fd')) return true         // IPv6 unique-local
  if (/^fe[89ab]/i.test(ip)) return true                              // IPv6 link-local (fe80::/10)
  if (ip === '::') return true                                        // IPv6 unspecified
  return false
}

// A DNS lookup that undici runs at the moment it is about to connect. The
// addresses we hand back are EXACTLY what undici dials — there is no second,
// unchecked lookup afterwards, so DNS rebinding has no window to exploit. We
// vet every address the name resolves to, and refuse the whole connection if
// any one of them is internal. (undici calls us with { all: true } and expects
// the full vetted list back, then connects to one of them — only to one we
// checked.)
function pinnedSafeLookup (
  hostname: string,
  options: LookupOneOptions | LookupAllOptions,
  callback: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void
): void {
  dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err != null) { callback(err, []); return }
    for (const { address } of addresses) {
      if (isInternalAddress(address)) {
        callback(new Error(`SSRF guard: ${hostname} resolves to internal address ${address}`), [])
        return
      }
    }
    callback(null, addresses) // every address here has passed the check
  })
}

// One shared HTTP client that enforces the connect-time address check for every
// outbound request this route makes. (The cast bridges Node's dns lookup type
// to undici's connector type — the runtime shapes match.)
const egressGuardedAgent = new Agent({ connect: { lookup: pinnedSafeLookup as any } })

// Cheap string pre-flight: must be a well-formed http(s) URL. The address check
// itself happens later, at connect time, in pinnedSafeLookup.
function assertHttpUrl (raw: string): void {
  const url = new URL(raw) // throws on a malformed / scheme-less URL
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http(s) URLs are allowed')
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
          assertHttpUrl(url) // reject non-http(s) before we touch the network
          // dispatcher: vet + pin the address at connect time (no rebinding gap).
          // redirect: 'manual': do NOT chase a 302 — it could point back inside.
          const response = await fetch(url, { dispatcher: egressGuardedAgent, redirect: 'manual' })
          if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
            throw new Error('Refusing to follow a redirect')
          }
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
