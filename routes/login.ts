/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'
import { z } from 'zod'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as models from '../models/index'
import { type User } from '../data/types'
import * as utils from '../lib/utils'

const LoginSchema = z.object({
  email: z.email().max(254),
  password: z.string().max(128)
})

export function login () {
  function afterLogin (user: User, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user)
    BasketModel.findOrCreate({ where: { UserId: user.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const authenticatedUser = { data: user, bid: basket.id } // keep track of original basket
        const token = security.authorize(authenticatedUser)
        security.authenticatedUsers.put(token, authenticatedUser)
        res.json({ authentication: { token, bid: basket.id, umail: user.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  return (req: Request, res: Response, next: NextFunction) => {
    // Parse the body once, at the edge. Anything that is not an email address
    // and a password fails like a wrong password, so the response gives
    // nothing away.
    const credentials = LoginSchema.safeParse(req.body)
    if (!credentials.success) {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }
    const { email, password } = credentials.data
    const passwordHash = security.hash(password)

    verifyPreLoginChallenges(email, password)

    const sql = `SELECT * FROM Users WHERE email = '${email}' AND password = '${passwordHash}' AND deletedAt IS NULL`

    models.sequelize.query(sql, { model: UserModel, plain: true })
      .then((authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (user.data?.id && user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data?.id) {
          afterLogin(user.data, res, next)
        } else {
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch((error: Error) => {
        next(error)
      })
  }

  function verifyPreLoginChallenges (email: string, password: string) {
    challengeUtils.solveIf(challenges.weakPasswordChallenge, () => { return email === 'admin@' + config.get<string>('application.domain') && password === 'admin123' })
    challengeUtils.solveIf(challenges.loginSupportChallenge, () => { return email === 'support@' + config.get<string>('application.domain') && password === 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P' })
    challengeUtils.solveIf(challenges.loginRapperChallenge, () => { return email === 'mc.safesearch@' + config.get<string>('application.domain') && password === 'Mr. N00dles' })
    challengeUtils.solveIf(challenges.loginAmyChallenge, () => { return email === 'amy@' + config.get<string>('application.domain') && password === 'K1f.....................' })
    challengeUtils.solveIf(challenges.dlpPasswordSprayingChallenge, () => { return email === 'J12934@' + config.get<string>('application.domain') && password === '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB' })
    challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => { return email === 'bjoern.kimminich@gmail.com' && password === 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
    challengeUtils.solveIf(challenges.exposedCredentialsChallenge, () => { return email === 'testing@' + config.get<string>('application.domain') && password === 'IamUsedForTesting' })
  }

  function verifyPostLoginChallenges (user: User) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => { return user.id === users.admin.id })
    challengeUtils.solveIf(challenges.loginJimChallenge, () => { return user.id === users.jim.id })
    challengeUtils.solveIf(challenges.loginBenderChallenge, () => { return user.id === users.bender.id })
    challengeUtils.solveIf(challenges.ghostLoginChallenge, () => { return user.id === users.chris.id })
    if (challengeUtils.notSolved(challenges.ephemeralAccountantChallenge) && user.email === 'acc0unt4nt@' + config.get<string>('application.domain') && user.role === 'accounting') {
      UserModel.count({ where: { email: 'acc0unt4nt@' + config.get<string>('application.domain') } }).then((count: number) => {
        if (count === 0) {
          challengeUtils.solve(challenges.ephemeralAccountantChallenge)
        }
      }).catch(() => {
        throw new Error('Unable to verify challenges! Try again')
      })
    }
  }
}
