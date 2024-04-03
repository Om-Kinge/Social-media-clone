import bcrypt, {genSalt} from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

/* ReGISTER USER */

export const register = async(req,res) => {
    try{
        const {
			firstName,
			lastName,
			email,
			password,
			picturePath,
			friends,
			location,
			occupation,
		} = req.body;
       
        const salt = await bcrypt.genSalt(10); // encryption
		const passwordHash = await bcrypt.hash(password, salt);

		const newUser = new User({
			firstName,
			lastName,
			email,
			password: passwordHash,
			picturePath,
			friends,
			location,
			occupation,
			viewedProfile: Math.floor(Math.random() * 10000),
			impressions: Math.floor(Math.random() * 10000),
		});
		const savedUser = await newUser.save();
		res.status(201).json(savedUser); // send the user to backend

    }catch(err) {
        res.status(500).json({error: err.message});
    }
};

/* LOGGING IN */

export const login = async (req, res) => {
	try {
		const {email, password} = req.body;
		const user = await User.findOne({email: email});

		if (!user) return res.status(400).json({msg: 'User does not exist.'});

		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch)return res.status(400).json({msg: 'Incorrect Password/Invalid Credentials'});

		const token = jwt.sign({id: user._id}, process.env.JWT_SECRET);

		delete user.password; // to keep safe it doesn't go to frontend
		res.status(200).json({token, user});

	} catch (err) {
		res.status(500).json({error: err.message});
	}
};