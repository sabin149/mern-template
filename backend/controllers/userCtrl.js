const User = require('../models/User')
const Note = require('../models/Note')
const bcrypt = require('bcrypt')


const getAllUsers = async (req, res) => {
    // Get all users from MongoDB
    const users = await User.find().select('-password').lean()

    // If no users 
    if (!users?.length) {
        return res.status(400).json({ message: 'No users found' })
    }

    res.json(users)
}

const createNewUser = async (req, res) => {
    const { fullname, email, password, confirmation_password, roles } = req.body
    // Confirm data
    if (!fullname || !email || !password || !confirmation_password) {
        return res.status(400).json({ message: 'All fields are required' })
    }

    if (fullname.length < 6) {
        return res.status(400).json({ message: 'FullName must be at least 6 characters' })
    }

    // regex for email validation that must includes @, gmail, . and com
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/

    if (!emailRegex.test(email) || email.includes('gmail') === false || email.includes('com') === false) {
        return res.status(400).json({ message: 'Invalid email' })
    }

    // Check for duplicate username
    const duplicate = await User.findOne({ email }).collation({ locale: 'en', strength: 2 }).lean().exec()

    if (duplicate) {
        return res.status(409).json({ message: 'Duplicate Email' })
    }

    if (!passwordRegex.test(password)) {
        return res.status(400).json({ message: 'Password must contain 8 characters with at least 1 uppercase, 1 lowercase, 1 number, 1 special character' })
    }

    if (password !== confirmation_password) {
        return res.status(400).json({ message: 'Password and Confirmation Password does not match' })
    }

    if (!roles || roles.length === 0 || !Array.isArray(roles) || !roles.length) {
        return res.status(400).json({ message: 'Roles is required' })
    }
    // Hash password 
    const hashedPwd = await bcrypt.hash(password, 10) // salt rounds

    // Create new user
    const newUser = new User({
        fullname,
        email,
        password: hashedPwd,
        roles,
        status: true
    })

    // Save user to database
    const savedUser = await newUser.save()

    // Create secure cookie with refresh token
    const accessToken = jwt.sign(
        {
            id: savedUser._id,
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
    )

    const refreshToken = jwt.sign(
        { id: savedUser._id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    )

    // Create secure cookie with refresh token 
    res.cookie('jwt', refreshToken, {
        httpOnly: true, //accessible only by web server 
        secure: false, //https
        sameSite: 'None', //cross-site cookie 
        maxAge: 7 * 24 * 60 * 60 * 1000 //cookie expiry: set to match rT
    })

    // Send accessToken containing email and roles 
    res.status(200).json({ message: `New User ${newUser.fullname.split(' ')[0]} Created`, accessToken, newUser })
}


const updateUser = async (req, res) => {
    const { id, fullname, email, roles, active } = req.body

    // Confirm data 
    if (!id || !fullname || !email || !Array.isArray(roles) || !roles.length || typeof active !== 'boolean') {
        return res.status(400).json({ message: 'All fields except password are required' })
    }

    // Does the user exist to update?
    const user = await User.findById(id).exec()

    if (!user) {
        return res.status(400).json({ message: 'User not found' })
    }

    // Check for duplicate 
    const duplicate = await User.findOne({ email }).collation({ locale: 'en', strength: 2 }).lean().exec()

    // Allow updates to the original user 
    if (duplicate && duplicate?._id.toString() !== id) {
        return res.status(409).json({ message: 'Duplicate email' })
    }

    user.fullname = fullname
    user.email = email
    user.roles = roles
    user.status = active

    const updatedUser = await user.save()

    res.json({ message: `${updatedUser.fullname} updated` })
}


const deleteUser = async (req, res) => {
    const { id } = req.body

    // Confirm data
    if (!id) {
        return res.status(400).json({ message: 'User ID Required' })
    }

    // Does the user still have assigned notes?
    // const note = await Note.findOne({ user: id }).lean().exec()
    // if (note) {
    //     return res.status(400).json({ message: 'User has assigned notes' })
    // }

    // Does the user exist to delete?
    const user = await User.findById(id).exec()

    if (!user) {
        return res.status(400).json({ message: 'User not found' })
    }

    const result = await user.deleteOne()

    const reply = `Username ${result.fullname} with ID ${result._id} deleted`

    res.json(reply)
}

module.exports = {
    getAllUsers,
    createNewUser,
    updateUser,
    deleteUser
}