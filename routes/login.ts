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
import { type User } from '../data/types'

/*
 * Bound the input first, then normalise it, then check the format. Capping the
 * length before any regex runs keeps a pathological input from ever reaching the
 * pattern matcher; normalising before validating means "  ADMIN@Juice-Sh.op "
 * and "admin@juice-sh.op" are the same identity rather than two different ones.
 *
 * `z.object` strips unknown keys rather than rejecting them: the OAuth flow in
 * frontend/src/app/oauth/oauth.component.ts posts an extra `oauth: true` that
 * this handler has no use for. Stripping keeps that client working while
 * guaranteeing only `email` and `password` ever leave this schema.
 */
const LoginRequestSchema = z.object({
  email: z.string().max(254).trim().toLowerCase().pipe(z.email()),
  password: z.string().min(1).max(128)
})

type LoginRequest = z.infer<typeof LoginRequestSchema>

/*
 * One response for every way a login can fail — malformed body, unknown email,
 * wrong password. Anything more specific is a user-enumeration oracle.
 */
function rejectCredentials (res: Response) {
  res.status(401).send(res.__('Invalid email or password.'))
}

export function login () {
  function afterLogin (user: User, res: Response, next: NextFunction) {
    verifyPostLoginChallenges(user)
    BasketModel.findOrCreate({ where: { UserId: user.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        /*
         * The session record kept server-side holds the whole user row, because
         * routes like changePassword read the password hash back out of it. The
         * JWT handed to the browser is a different, smaller object: a JWT is
         * signed, not encrypted, so anything in it is readable by whoever holds
         * it. Only the claims a client actually needs go in.
         */
        const authenticatedUser = { data: user, bid: basket.id } // keep track of original basket
        const token = security.authorize({
          data: {
            id: user.id,
            email: user.email,
            role: user.role,
            profileImage: user.profileImage,
            lastLoginIp: user.lastLoginIp,
            isActive: user.isActive
          },
          bid: basket.id
        })
        security.authenticatedUsers.put(token, authenticatedUser)
        res.json({ authentication: { token, bid: basket.id, umail: user.email } })
      })
      .catch((error: Error) => {
        next(error)
      })
  }

  return (req: Request, res: Response, next: NextFunction) => {
    const parsedBody = LoginRequestSchema.safeParse(req.body)
    if (!parsedBody.success) {
      rejectCredentials(res)
      return
    }
    const credentials = parsedBody.data

    verifyPreLoginChallenges(credentials)

    /*
     * The credentials are passed as bound parameters, not spliced into a query
     * string. Sequelize sends the statement and the values separately, so the
     * database parses the query shape once and can never be talked into reading
     * an apostrophe in an email address as the end of a string literal.
     *
     * `UserModel` is declared `paranoid: true`, so the `deletedAt IS NULL` guard
     * the old hand-written SQL carried is applied automatically.
     */
    UserModel.findOne({
      where: {
        email: credentials.email,
        password: security.hash(credentials.password)
      }
    })
      .then((authenticatedUser: UserModel | null) => {
        if (authenticatedUser === null) {
          rejectCredentials(res)
          return
        }
        if (authenticatedUser.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: authenticatedUser.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
          return
        }
        afterLogin(authenticatedUser, res, next)
      })
      .catch((error: Error) => {
        next(error)
      })
  }

  function verifyPreLoginChallenges (credentials: LoginRequest) {
    challengeUtils.solveIf(challenges.weakPasswordChallenge, () => {
      return (
        credentials.email === 'admin@' + config.get<string>('application.domain') &&
        credentials.password === 'admin123'
      )
    })
    challengeUtils.solveIf(challenges.loginSupportChallenge, () => {
      return (
        credentials.email === 'support@' + config.get<string>('application.domain') &&
        credentials.password === 'J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P'
      )
    })
    challengeUtils.solveIf(challenges.loginRapperChallenge, () => {
      return (
        credentials.email === 'mc.safesearch@' + config.get<string>('application.domain') &&
        credentials.password === 'Mr. N00dles'
      )
    })
    challengeUtils.solveIf(challenges.loginAmyChallenge, () => {
      return (
        credentials.email === 'amy@' + config.get<string>('application.domain') &&
        credentials.password === 'K1f.....................'
      )
    })
    challengeUtils.solveIf(challenges.dlpPasswordSprayingChallenge, () => {
      return (
        credentials.email === 'j12934@' + config.get<string>('application.domain') &&
        credentials.password === '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'
      )
    })
    challengeUtils.solveIf(challenges.oauthUserPasswordChallenge, () => {
      return (
        credentials.email === 'bjoern.kimminich@gmail.com' &&
        credentials.password === 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      )
    })
    challengeUtils.solveIf(challenges.exposedCredentialsChallenge, () => {
      return (
        credentials.email === 'testing@' + config.get<string>('application.domain') &&
        credentials.password === 'IamUsedForTesting'
      )
    })
  }

  function verifyPostLoginChallenges (user: User) {
    challengeUtils.solveIf(challenges.loginAdminChallenge, () => {
      return user.id === users.admin.id
    })
    challengeUtils.solveIf(challenges.loginJimChallenge, () => {
      return user.id === users.jim.id
    })
    challengeUtils.solveIf(challenges.loginBenderChallenge, () => {
      return user.id === users.bender.id
    })
    challengeUtils.solveIf(challenges.ghostLoginChallenge, () => {
      return user.id === users.chris.id
    })
    if (
      challengeUtils.notSolved(challenges.ephemeralAccountantChallenge) &&
      user.email === 'acc0unt4nt@' + config.get<string>('application.domain') &&
      user.role === 'accounting'
    ) {
      UserModel.count({
        where: { email: 'acc0unt4nt@' + config.get<string>('application.domain') }
      })
        .then((count: number) => {
          if (count === 0) {
            challengeUtils.solve(challenges.ephemeralAccountantChallenge)
          }
        })
        .catch(() => {
          throw new Error('Unable to verify challenges! Try again')
        })
    }
  }
}
