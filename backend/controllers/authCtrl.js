const User = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const transporter = require('../config/emailConfig');

// regex expression for password validation that must contain at least 1 uppercase, 1 lowercase, 1 number, 1 special character
const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/

const register = async (req, res) => {
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
        roles
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

    const link = `http://localhost:3000/verify-user/${newUser._id}/${accessToken}`;

    let info = await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: email,
        subject: 'Account Verification',
        html: `
                  <h1> Account Verification </h1> <br/>
                  <h2>
                      <a href="${link}">Click Here</a> to Verify Your Account</h2>`
    });

    // Send accessToken containing email and roles 
    res.status(200).json({ message: "Account Verification Link Sent Successfully, Check Your Mail", info, accessToken, newUser })
}

const login = async (req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        return res.status(400).json({ message: 'All fields are required' })
    }

    const foundUser = await User.findOne({ email }).exec()

    if (!foundUser) {
        return res.status(401).json({ message: 'User not found' })
    }

    const match = await bcrypt.compare(password, foundUser.password)

    if (!match) return res.status(401).json({ message: 'Password doesnot match' })



    const accessToken = jwt.sign(
        {
            id: foundUser._id,
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }

    )

    if (foundUser.active === false) {
        const link = `http://localhost:3000/verify-user/${foundUser._id}/${accessToken}`;

        console.log(link);

        // let info = await transporter.sendMail({
        //     from: process.env.EMAIL_FROM,
        //     to: email,
        //     subject: 'Account Verification',
        //     html: `
        //               <h1> Account Verification </h1> <br/>
        //               <h2>
        //                   <a href="${link}">Click Here</a> to Verify Your Account</h2>`
        // });
        res.status(200).json({ message: "Account Verification Link Sent Successfully, Check Your Mail", info: "bb", foundUser })

    }

    if (foundUser.active === true) {
        const refreshToken = jwt.sign(
            { id: foundUser._id },
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
        res.json(
            {
                accessToken,
                message: `Welcome ${foundUser.fullname}`
            }
        )
    }

}

const verifyUser = async (req, res) => {
    const { id, token } = req.params;
    const user = await User.findById(id);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    if (user) {
        const newUser = await User.findByIdAndUpdate(user._id, { $set: { active: true } }).exec();
        res.status(200).json({
            message: `${newUser.fullname.split(' ')[0]}, your account has been verified successfully`,

        });
    } else {
        res.status(400).json({ message: "User Doesn't Exists" });
    }
}

const refresh = (req, res) => {
    const cookies = req.cookies

    if (!cookies?.jwt) return res.status(401).json({ message: 'Unauthorized' })
    const refreshToken = cookies.jwt

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err) return res.status(403).json({ message: 'Forbidden' })

            const foundUser = await User.findOne({ _id: decoded.id }).exec()

            if (!foundUser) return res.status(401).json({ message: 'Unauthorized' })

            const accessToken = jwt.sign(
                {
                    id: foundUser._id,
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '15m' }
            )

            res.json({ accessToken })
        }
    )
}

const logout = (req, res) => {
    const cookies = req.cookies
    if (!cookies?.jwt) return res.sendStatus(204) //No content
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
    res.json({ message: 'Logout Successfully' })
}

const sendUserPaswordResetEmail = async (req, res) => {
    const { email } = req.body;
    if (email) {
        const user = await User.findOne({ email });
        if (user) {
            const token = jwt.sign({
                id: user._id
            },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '15m' });


            const link = `http://localhost:3000/${user._id}/${token}`;

            // console.log(link)

            // console.log("<------------------------------------------>")

            let info = await transporter.sendMail({
                from: process.env.EMAIL_FROM,
                to: user.email,
                subject: 'Password Reset Link',
                html: `
                  <h1>Password Reset Link</h1> <br/>
                  <h2>
                      <a href="${link}">Click Here</a> to Reset Your Password</h2>`
            });

            res.status(200).json({ message: "Password Reset Link Sent Successfully, Check Your Mail", info });
        } else {
            res.status(400).json({ message: "Email doesn't exist" });
        }
    } else {
        res.status(400).json({ message: "Email field is required" })
    }
}

const resetUserPassword = async (req, res) => {
    const { password, confirmation_password } = req.body;
    const { id, token } = req.params;

    const user = await User.findById(id);
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
    if (password && confirmation_password) {
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ message: 'Invalid Password' })
        }
        if (password === confirmation_password) {

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            await User.findByIdAndUpdate(user._id, { $set: { password: hashedPassword } });

            res.status(200).json({ message: "Password Reset Successfully" });

        } else {
            res.status(400).json({ message: "Password and Confirmation Password Doesn't Match" });
        }
    } else {
        res.status(400).json({ message: "All fields are required" });
    }
}

const changeUserPassword = async (req, res) => {
    const { old_password, password, confirmation_password } = req.body;

    if (old_password && password && confirmation_password) {
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ message: 'Password must contain 8 characters with at least 1 uppercase, 1 lowercase, 1 number, 1 special character' })
        }

        const isMatch = await bcrypt.compare(old_password, req.user.password)
        if (!isMatch) return res.status(400).json({ message: " Old Password is incorrect." })

        const checkMatch = old_password === password;
        if (checkMatch) return res.status(400).json({ message: "Old Password and New Password are same." })

        if (password !== confirmation_password) return res.status(400).json({ message: "Password and Confirmation Password Doesn't Match" })
        const newHashedPassword = await bcrypt.hash(password, 10)

        await User.findByIdAndUpdate(req.user._id, { $set: { password: newHashedPassword } });

        res.json({
            message: 'Password Changed Successfully'
        })

    } else {
        res.status(400).json({ message: "All fields are required" })

    }
}

module.exports = {
    register,
    login,
    verifyUser,
    refresh,
    logout,
    sendUserPaswordResetEmail,
    resetUserPassword,
    changeUserPassword
}