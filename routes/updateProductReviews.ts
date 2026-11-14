/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const reviewId = req.body.id
    const message = req.body.message

    // An object such as { $ne: -1 } is a query operator, not an id.
    if (!user || typeof reviewId !== 'string' || typeof message !== 'string') {
      res.status(400).json({ error: 'Invalid review update.' })
      return
    }

    // One review, and only if the caller wrote it.
    const filter = { _id: reviewId, author: user.data.email }
    const change = { $set: { message } }
    const options = { multi: false }

    db.reviewsCollection.update(filter, change, options).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
