const User = require('../model/User')

const handleLogout = async (req, res) => {
    // On client, also delete the accessToken on the front end
    const cookies = req.cookies
    if (!cookies?.jwt) return res.sendStatus(204) // No content
    const refreshToken = cookies.jwt

    // Is refresh token in db?
    const foundUser = await User.findOne({ refreshToken }).exec()
    if (!foundUser) {
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None' }) // in production we will want the secure: true
        return res.sendStatus(204)
    }
    
    foundUser.refreshToken = foundUser.refreshToken.filter(token => token !== refreshToken)
    const result = await foundUser.save()

    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None' }) // in production we will want the secure: true
    res.sendStatus(204)
}

module.exports = { handleLogout }