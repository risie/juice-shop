/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
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

      try {
        const response = await fetch(imageUrl)
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
