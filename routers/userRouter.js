const express = require('express');
const bcrypt = require('bcrypt');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { User, validate } = require('../models/user');

const router = express.Router();

const newUser = async (req, res) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    let user = await User.findOne({ email: req.body.email });
    if (user) return res.status(400).send('User already registered!');

    user = new User(_.pick(req.body, ['email', 'password', 'username']));

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);

    const token = user.generateJWT();

    const result = await user.save();

    const { bio, interests } = req.body;
    const userId = result._id;

    try {
        await axios.post(`${process.env.BACKEND_2_URL}/profile`, 
           { userId, bio, interests },
           { headers: { Authorization: `Bearer ${jwt.sign({}, process.env.JWT_SECRET_KEY)}` } }
        );
    } catch (err) {
        console.error('Error forwarding data to Backend 2:', err.response || err.message);
        return res.status(500).send('Error forwarding data to Backend 2');
    }
    

    return res.status(201).send({
        token,
        user: _.pick(result, ['_id', 'email', 'username']),
    });
};

router.post('/', newUser);

module.exports = router;
