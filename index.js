const express = require('express')
const bodyParser = require('body-parser')
const AWS = require('aws-sdk')
const passport = require('passport')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const logger = require('./logger.js')

const options = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET
}

passport.use(new JwtStrategy(options, (jwtPayload, done) => {
  // Your validation logic here. For service-to-service auth, you may look at the 'service' field in the payload
  if (jwtPayload.service === process.env.SERVICE_KEY) {
    return done(null, { service: process.env.SERVICE_KEY })
  } else {
    return done(null, false)
  }
}))

const app = express()
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(passport.initialize())

app.post('/api/sign', passport.authenticate('jwt', { session: false }), async (req, res) => {
  // AWS KMS
  const KEY_ID = process.env.KMS_KEY_ID
  const KMS = new AWS.KMS({
    region: process.env.AWS_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY
  })

  const signParams = {
    KeyId: KEY_ID,
    Message: req.body.iconTxHash,
    SigningAlgorithm: 'ECDSA_SHA_256',
    MessageType: 'DIGEST'
  }
  const signResponse = await KMS.sign(signParams).promise()
  res.json({ message: signResponse })
})

app.get('/', function (req, res) {
  res.json({ message: 'Express is up!' })
})

app.listen(3000, function () {
  logger.info('Express is running on port 3000')
})
