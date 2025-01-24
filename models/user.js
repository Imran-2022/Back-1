const jwt = require('jsonwebtoken');
const Joi = require('joi');
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        minlength: 5,
        maxlength: 255,
    },
    password: {
        type: String,
        required: true,
        minlength: 5,
        maxlength: 1024,
    },
    username: {
        type: String,
        required: true,
        minlength: 3,
        maxlength: 20,
    },
});

userSchema.methods.generateJWT = function () {
    return jwt.sign({ id: this._id, email: this.email, username: this.username }, process.env.JWT_SECRET_KEY, {
        expiresIn: '3h',
    });
};

const validateUser = (user) => {
    const schema = Joi.object({
        email: Joi.string().min(5).max(255).required().email(),
        password: Joi.string().min(5).max(255).required(),
        username: Joi.string().min(3).max(20).required(),
        bio: Joi.string().min(1).max(200).required(),
        interests: Joi.string().min(1).max(200).required(),
    });

    return schema.validate(user);
};

module.exports.User = mongoose.model('User', userSchema);
module.exports.validate = validateUser;
