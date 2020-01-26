require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

//Generate access tokens in node and store in env file -> require('crypto').randomBytes(64).toString('hex')
app.use(express.json())

const codeRepos = [
  {
    username: 'swetlina',
    repo: 'Repo 1'
  },
  {
    username: 'Jim',
    repo: 'Repo 2'
  }
]

app.get('/codeRepos', authenticateToken, (req, res) => {
  res.json(codeRepos.filter(repo => repo.username === req.user.name))
})

//auth-check middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(401)

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decode) => {
    console.log(err)
    if (err) return res.sendStatus(403)
    req.user = {name: decode.name}
    next()
  })
}

app.listen(3000)