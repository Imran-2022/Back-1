const express = require('express');
const bcrypt = require('bcrypt');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { User, validate } = require('../models/user');

const router = express.Router();

// Function to create a new user
const newUser = async (req, res) => {
    // Validate the request body to ensure it meets the user schema
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);  // Return error if validation fails

    // Check if a user already exists with the provided email
    let user = await User.findOne({ email: req.body.email });
    if (user) return res.status(400).send('User already registered!');  // Return error if user already exists

    // Create a new user from the request body, picking only the necessary fields
    user = new User(_.pick(req.body, ['email', 'password', 'username']));

    // Hash the password using bcrypt
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);

    // Generate a JWT token for the user
    const token = user.generateJWT();

    // Save the user to the database
    const result = await user.save();

    const { bio, interests } = req.body;
    const userId = result._id;

    try {
        // Forward the user's profile data to Backend 2 (via API request)
        await axios.post(`${process.env.BACKEND_2_URL}/profile`, 
            { userId, bio, interests },
            { headers: { Authorization: `Bearer ${jwt.sign({}, process.env.JWT_SECRET_KEY)}` } }
        );
    } catch (err) {
        console.error('Error forwarding data to Backend 2:', err.response || err.message);  // Log error if API request fails
        return res.status(500).send('Error forwarding data to Backend 2');  // Return error response
    }

    // Return success response with the user's token and basic details
    return res.status(201).send({
        token,
        user: _.pick(result, ['_id', 'email', 'username']),
    });
};

// Function to retrieve user data by userId
const userData = async (req, res) => {
    const userId = req.params.id;  // Get the userId from the URL parameter

    try {
        // Fetch sensitive data (username, email) from Backend 1
        const sensitiveData = await User.findById(userId).select('username email');
        if (!sensitiveData) {
            return res.status(404).send('User not found.');  // Return error if user not found
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

        // Send the combined response with both sensitive and non-sensitive data
        return res.status(200).send(combinedData);
    } catch (err) {
        console.error('Error retrieving user data:', err.response?.data || err.message);  // Log error for debugging

        if (err.response?.status === 404) {
            return res.status(404).send('User not found.');  // Return error if user not found in Backend 2
        }

        return res.status(500).send('An error occurred while retrieving user data.');  // Return server error response
    }
};

// Define routes for handling user-related requests
router.post('/', newUser);  // POST to create a new user
router.get('/:id', userData);  // GET to fetch user data by userId

module.exports = router;  // Export the router to be used in other parts of the application
