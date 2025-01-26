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


const userData = async (req, res) => {
    const userId = req.params.id;

    try {
        // Fetch sensitive data (username, email) from Backend 1
        const sensitiveData = await User.findById(userId).select('username email');
        if (!sensitiveData) {
            return res.status(404).send('User not found.');
        }

        // Convert sensitiveData to a plain JavaScript object
        const sensitiveDataPlain = sensitiveData.toObject();

        // Fetch non-sensitive data (bio, interests) from Backend 2
        const backend2Response = await axios.get(`${process.env.BACKEND_2_URL}/profile/${userId}`, {
            headers: { Authorization: `Bearer ${jwt.sign({}, process.env.JWT_SECRET_KEY)}` },
        });

        const nonSensitiveData = backend2Response.data;

        // Combine data from both backends
        const combinedData = {
            ...sensitiveDataPlain,
            ...nonSensitiveData,
        };

        // Send the combined response
        return res.status(200).send(combinedData);
    } catch (err) {
        console.error('Error retrieving user data:', err.response?.data || err.message);

        if (err.response?.status === 404) {
            return res.status(404).send('User not found.');
        }

        return res.status(500).send('An error occurred while retrieving user data.');
    }
};


router.post('/', newUser);
router.get('/:id', userData);

module.exports = router;
