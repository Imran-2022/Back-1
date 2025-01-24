const express =require('express');
const bcrypt = require('bcrypt');
const _=require('lodash');
const {User,validate} = require('../models/user');
const authorize=require('../middlewares/authorize');

const router = express.Router();
const newUser = async(req,res)=>{
    const {error}=validate(req.body);
    if(error)return res.status(400).send(error.details[0].message);
    
    let user =await User.findOne({email:req.body.email});
    if(user)return res.status(400).send('user already registered !');

    // user = new User({email:req.body.email,password:req.body.password});
    user = new User(_.pick(req.body,['email','password','username']));

    const salt=await bcrypt.genSalt(10);
    user.password=await bcrypt.hash(user.password,salt);

    const token=user.generateJWT();

    const result=await user.save();
    return res.status(201).send({
        token:token,
        user:_.pick(result,['_id','email','username'])
    });

}

const authUser= async(req,res)=>{
    let user = await User.findOne({email:req.body.email});
    if(!user)return res.status(400).send("invalid email or passowrd!");

    const validUser=await bcrypt.compare(req.body.password,user.password);
    if(!validUser)return res.status(400).send("invalid email or passowrd");

    const  token =user.generateJWT();
    res.send({
        token:token,
        user:_.pick(user,['_id','email','username'])
    })
}
// Fetch user details by ID
router.get('/:id', authorize, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password'); // Exclude the password field
        if (!user) return res.status(404).send('User not found');
        res.send(user);
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Update user details (username and email)
router.put('/:id', authorize, async (req, res) => {
    const { username, email } = req.body;
    
    try {
        let user = await User.findById(req.params.id);
        if (!user) return res.status(404).send('User not found');

        user.username = username || user.username;
        user.email = email || user.email;

        const updatedUser = await user.save();
        res.send(_.pick(updatedUser, ['_id', 'username', 'email']));
    } catch (error) {
        res.status(500).send('Server error');
    }
});


router.route('/')
    .post(newUser)

router.route('/auth')
    .post(authUser)

module.exports=router;