const User = require('../model/User')
const ROLES_LIST = require('../config/roles_list')


const getAllUsers = async (req, res) => {
    const users = await User.find().exec()
    if (!users) return res.status(204).json({ 'message': 'No users found.' })
    res.json(users);
}

// Bonus points
const updateUserRoles = async (req, res) => {
    if (!req?.body?.id) {
        return res.status(400).json({ 'message': 'ID parameter is required.' })
    }

    const user = await User.findById(req.body.id).exec()
    if (!user) {
        return res.status(400).json({ "message": `No user matches ID ${req.body.id}.` })
    }
    // NEEDS SOME WORK
    // Specifically, we would want to cross reference the array passed in against our global ROLES_LIST variable to ensure that the correct roles are being assigned WITHOUT giving away what the codes signify on our front-end. We don't want malicious actors to know what number code applies for Admin and in a real example might even want to salt and hash the numbers from some kind of drop-down before adding them to our payload for extra tight security... I'm not going this far 
    const rolesArray = Object.values(user.roles)
    if (req.body?.roles) rolesArray.push(...req.body?.roles)
    // gives us all the codes without their keys
    const rolesAllowed = Object.entries(ROLES_LIST)
    // then we take whatever values were passed in the req.body.roles, see which we are adding and we add the corresponding key/value pair to that user's roles. Again, I am not going to do this now but I think I get how.
    console.log(rolesArray, rolesAllowed)
    rolesAllowed.forEach(role => {
        if (rolesArray.includes(role[1])) user.roles[role[0]] = role[1]
    })

    const result = await user.save()

    // THIS STILL NEEDS WORK
    // We would want some way to remove permissions as well, which this code does not currently allow

    res.json(result)
}

const deleteUser = async (req, res) => {
    if (!req?.body?.id) {
        return res.status(400).json({ 'message': 'ID parameter is required.' })
    }
    const user = await User.findById(req.body.id).exec()
    if (!user) {
        return res.status(400).json({ "message": `No user matches ID ${req.body.id}.` })
    }

    const result = await user.deleteOne({ _id: req.body.id })

    res.json(result)
}

const getUser = async (req, res) => {
    if (!req?.params?.id) {
        return res.status(400).json({ 'message': 'ID parameter is required.' })
    }

    const user = await User.findById(req.params.id).exec()
    if (!user) {
        return res.status(400).json({ "message": `No user matches ID ${req.params.id}.` })
    }
    res.json(user)
}

module.exports = {
    getAllUsers,
    updateUserRoles,
    deleteUser,
    getUser
}