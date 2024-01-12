const User = require('../model/User')
const jwt = require('jsonwebtoken')

const handleRefreshToken = async (req, res) => {
    const cookies = req.cookies
    if (!cookies?.jwt) return res.sendStatus(401)
    const refreshToken = cookies.jwt
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true }) // in production we will want the secure: true

    const foundUser = await User.findOne({ refreshToken }).exec()

    // Detected refresh token reuse!
    if (!foundUser) {
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            async (err, decoded) => {
                if (err) return res.sendStatus(403) //Forbidden 
                console.log('attempted refresh token reuse!')
                const hackedUser = await User.findOne({ username: decoded.username }).exec()
                // You could add a line in the Schema for accessToken as well and cross-reference the access tokens for reuse as well, but it would involve a lot more code. The below code is basically just wiping out all the refresh tokens saved for a given user, forcing a new login when the current access tokens expire.
                hackedUser.refreshToken = []
                const result = await hackedUser.save()
                console.log(result)
            }
        )
        return res.sendStatus(403) //Forbidden 
    }

    const newRefreshTokenArray = foundUser.refreshToken.filter(rt => rt !== refreshToken)
    // evaluate jwt 
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err) {
                console.log('expired refresh token')
                foundUser.refreshToken = [...newRefreshTokenArray]
                const result = await foundUser.save()
                console.log(result)
            }
            if (err || foundUser.username !== decoded.username) return res.sendStatus(403)

            // Refresh token was still valid
            const roles = Object.values(foundUser.roles)
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": decoded.username,
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
            // Saving refreshToken with current user
            foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken]
            const result = await foundUser.save()
            console.log(result)

            res.cookie('jwt', newRefreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 }) // in production we will want the secure: true

            res.json({ accessToken })
        }
    )
}

module.exports = { handleRefreshToken }