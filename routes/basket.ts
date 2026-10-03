/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = req.params.id
      // Authorise against the authenticated caller, not the id in the URL.
      // Scoping the query to the caller's own UserId means a basket that
      // isn't theirs simply isn't found — the id can be tampered with all
      // day and the row never comes back.
      const ownerId = security.authenticatedUsers.from(req)?.data.id
      const basket = ownerId
        ? await BasketModel.findOne({
          where: { id, UserId: ownerId },
          include: [{ model: ProductModel, paranoid: false, as: 'Products' }]
        })
        : null
      if (((basket?.Products) != null) && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
