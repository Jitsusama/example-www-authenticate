import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
import express from 'express'

const SECRET = 'eggs for breakfast'

/**
 * @type RequestHandler
 * @param {Request} req
 * @param {Response} res
 * @param {NextFunction} next
 */
const requestLogger = (req, res, next) => {
    console.info({
        time: new Date(),
        layer: 'request',
        method: req.method,
        path: req.path,
        headers: {
            authorization: req.header('authorization'),
            cookie: req.header('cookie')
        }
    })
    next()
}

/**
 * @type RequestHandler
 * @param {Request} req
 * @param {Response} res
 * @param {NextFunction} next
 */
const responseLogger = (req, res, next) => {
    console.info({
        time: new Date(),
        layer: 'response',
        status: res.statusCode,
        headers: res.getHeaders()
    })
    next()
}

/**
 * @type RequestHandler
 * @param {Error} error
 * @param {Request} req
 * @param {Response} res
 * @param {NextFunction} next
 */
const errorHandler = (error, req, res, next) => {
    if (error.message === 'authenticate')
        res.status(401).set({'WWW-Authenticate': 'Basic realm="Credentials"'}).send()
    else
        res.status(500).send()
    next()
}

/**
 * @type RequestHandler
 * @param {Request} req
 * @param {Response} res
 * @param {NextFunction} next
 */
const requestAuthorizer = (req, res, next) => {
    const {authorization} = req.headers
    const {'Access-Token': accessToken} = req.cookies
    console.info({time: new Date(), layer: 'auth', authorization, accessToken})
    if (!authorization && !accessToken)
        next(new Error('authenticate'))
    else if (accessToken)
        jwt.verify(accessToken, SECRET, {}, (error, data) => {
            if (error) next(new Error('authenticate'))
            else {
                req.body = data
                next()
            }
        })
    else if (!validateCredentials(authorization))
        next(new Error('authenticate'))
    else
        jwt.sign({authz: ['thing1', 'thing2']}, SECRET, {}, (error, token) => {
            // noinspection JSValidateTypes
            req.body = {authz: ['thing1', 'thing2']}
            res.set({'Set-Cookie': `Access-Token=${token};Path=/;HttpOnly`})
            next()
        })
}

/** @param {string} authorization */
const validateCredentials = authorization => {
    const {type, value} = authorization.match(/^(?<type>[^\s]+)\s+(?<value>.+)/)?.groups || {}
    if (type !== 'Basic') {
        console.info({time: new Date(), layer: 'validate', type, value})
        return false
    }
    const credentials = Buffer.from(value, 'base64').toString('utf-8')
    const [username, password] = credentials.split(/:/)
    console.info({time: new Date(), layer: 'validate', username, password})
    return username === 'user' && password === 'password'
}

express()
    .use(requestLogger)
    .use(cookieParser())
    .use(requestAuthorizer)
    .get('/', (req, res, next) => {
        res.contentType('text/html').send(`<html lang="en">
<head><title>WWW-Authenticate Example</title></head>
<body><p>${req.body.authz}</p></body>
</html>`)
        next()
    })
    .use(errorHandler)
    .use(responseLogger)
    .listen(8192, () => console.info('listening for requests'))
