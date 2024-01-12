const User = require('../model/User')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const handleLogin = async (req, res) => {
    const cookies = req.cookies

    const { user, pwd } = req.body
    if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' })

    const foundUser = await User.findOne({ username: user }).exec()

    if (!foundUser) return res.sendStatus(401) //Unauthorized 
    // evaluate password 
    const match = await bcrypt.compare(pwd, foundUser.password)
    if (match) {
        const roles = Object.values(foundUser.roles).filter(Boolean)
        // create JWTs
        const accessToken = jwt.sign(
            {
                "UserInfo": {
                    "username": foundUser.username,
                    "roles": roles
                }
            },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: '10s' }
        )
        const newRefreshToken = jwt.sign(
            { "username": foundUser.username },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: '15m' }
        )

        let newRefreshTokenArray = !cookies?.jwt ? foundUser.refreshToken : foundUser.refreshToken.filter(rt => rt !== cookies.jwt)

        // checking to see if a refresh token has been used after being stolen when a user has not logged out, and then emptying their refreshToken array in the db forcing them to re-login
        if (cookies?.jwt) {
            const refreshToken = cookies.jwt
            const foundToken = await User.findOne({ refreshToken }).exec()

            if (!foundToken) {
                console.log('attempted refresh token reuse at login!')
                newRefreshTokenArray = []
            }
            res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true }) // in production we will want the secure: true
        }

        // Saving refreshToken with current user
        foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken]
        const result = await foundUser.save()
        console.log(result)

        res.cookie('jwt', newRefreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 }) // in production we will want the secure: true
        res.json({ accessToken })
    } else {
        res.sendStatus(401)
    }
}

module.exports = { handleLogin }