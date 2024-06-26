import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import multer from 'multer';
import helmet from 'helmet';
import morgan from 'morgan';
import path, {dirname} from 'path';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import postRoutes from './routes/posts.js';
import User from './models/User.js';
import Post from './models/Post.js';

import {fileURLToPath} from 'url';

import {login, register} from './controllers/auth.js';
import {createPost} from './controllers/posts.js';
import {verifyToken} from './middleware/auth.js';
import {users, posts} from './data/index.js';

//  Configurations
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// __filename = Current File Name './index.js'
//__dirname = Current Directory Name '../server'

dotenv.config();
const app = express();
// app instance of express;

app.use(express.json());
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({policy: 'cross-origin'}));
app.use(morgan('common'));
app.use(express.json({limit: '30mb', extended: true}));
app.use(bodyParser.json({limit: '30mb', extended: true}));
app.use(cors());
app.use("/assets", express.static(path.join(__dirname, "/public/assets")));

//File Storage

const storage = multer.diskStorage({
	destination: function (req, file, cb) {
		cb(null, "public/assets");
	},
	filename: function (req, file, cb) {
		cb(null, file.originalname);
	},
});

const upload = multer({storage});

//Routes with Files
app.post('/auth/register', upload.single('picture'), register);
app.post('/posts', verifyToken, upload.single('picture'), createPost);

// Routes
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/posts', postRoutes);

// MONGOOSE SETUP
const PORT = process.env.PORT || 6001;
mongoose
	.connect(process.env.MONGO_URL, {
		useNewUrlParser: true,
		useUnifiedTopology: true,
	})
	.then(() => {
		app.listen(PORT, () => console.log(`Server Port: ${PORT}`));

		//Add Data
		// User.insertMany(users);
		// Post.insertMany(posts);
	})
	.catch((error) => console.log(`${error} did not connect `));