const winston = require('winston')
const { format } = winston
const { combine, timestamp, json, colorize, uncolorize, printf } = format
require('winston-daily-rotate-file')

const fileRotateTransport = new winston.transports.DailyRotateFile({
  filename: 'logs/log-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  maxFiles: '1d',
  maxsize: '1m',
  zippedArchive: true,
  format: combine(uncolorize(), json())
})

const customColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  verbose: 'cyan',
  debug: 'blue',
  silly: 'grey'
}

winston.addColors(customColors)

const logger = winston.createLogger({
  format: combine(
    colorize(),
    timestamp({
      format: 'MMM-DD-YYYY HH:mm:ss'
    }),
    printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
  ),
  level: 'debug',
  transports: [fileRotateTransport, new winston.transports.Console()]
})

module.exports = logger
