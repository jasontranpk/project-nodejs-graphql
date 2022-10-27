const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const Post = require('../models/post');
const User = require('../models/user');
const { clearImage } = require('../helpers/file');

module.exports = {
	createUser: async function ({ userInput }, req) {
		const existingUser = await User.findOne({ email: userInput.email });

		const errors = [];
		if (!validator.isEmail(userInput.email)) {
			errors.push({ message: 'Email is invalid' });
		}
		if (
			validator.isEmpty(userInput.password) ||
			!validator.isLength(userInput.password, { min: 5 })
		) {
			errors.push({ message: 'Password too short' });
		}
		console.log(errors);
		if (errors.length > 0) {
			const error = new Error('Invalid input.');
			error.data = errors;
			throw error;
		}
		if (existingUser) {
			const error = new Error('Email exists already!');
			error.code = 422;
			throw error;
		}
		const hashedPassword = await bcrypt.hash(userInput.password, 12);
		const user = new User({
			email: userInput.email,
			password: hashedPassword,
			name: userInput.name,
		});
		const createdUser = await user.save();
		return { ...createdUser._doc, _id: createdUser._id.toString() };
	},
	login: async function ({ email, password }) {
		const user = await User.findOne({ email: email });
		if (!user) {
			const error = new Error('User not found');
			error.code = 401;
			throw error;
		}
		const isEqual = await bcrypt.compare(password, user.password);
		if (!isEqual) {
			const error = new Error('Password is invalid');
			error.code = 401;
			throw error;
		}

		const token = jwt.sign(
			{
				userId: user._id.toString(),
				email: user.email,
			},
			'somesupersecretsecret',
			{ expiresIn: '1h' }
		);

		return { token, userId: user._id.toString() };
	},
	createPost: async function ({ postInput }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}
		const errors = [];
		if (!validator.isLength(postInput.title, { min: 3 })) {
			errors.push({ message: 'Title is too short' });
		}
		if (!validator.isLength(postInput.content, { min: 5 })) {
			errors.push({ message: 'Content is too short' });
		}
		if (errors.length > 0) {
			const error = new Error('Invalid input.');
			error.data = errors;
			throw error;
		}
		const user = await User.findById(req.userId);
		if (!user) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}
		const post = new Post({
			title: postInput.title,
			content: postInput.content,
			imageUrl: postInput.imageUrl,
			creator: user,
		});
		const savedPost = await post.save();
		user.posts.push(savedPost);
		await user.save();
		return {
			...savedPost._doc,
			_id: savedPost._id.toString(),
			createdAt: savedPost.createdAt.toISOString(),
			updatedAt: savedPost.updatedAt.toISOString(),
		};
	},
	posts: async function ({ page }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}
		if (!page) {
			page = 1;
		}
		const perPage = 2;
		const totalPosts = await Post.find().countDocuments();
		const posts = await Post.find()
			.skip((page - 1) * perPage)
			.limit(perPage)
			.sort({ createdAt: -1 })
			.populate('creator');
		return {
			posts: posts.map((post) => {
				return {
					...post._doc,
					_id: post._id.toString(),
					createdAt: post.createdAt.toISOString(),
					updatedAt: post.updatedAt.toISOString(),
				};
			}),
			totalPosts,
		};
	},
	post: async function ({ postId }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}
		const post = await Post.findById(postId).populate('creator');
		if (!post) {
			const error = new Error('No post found');
			error.code = 404;
			throw error;
		}
		return {
			...post._doc,
			_id: post._id.toString(),
			createdAt: post.createdAt.toISOString(),
			updatedAt: post.updatedAt.toISOString(),
		};
	},
	updatePost: async function ({ id, postInput }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}
		const post = await Post.findById(id).populate('creator');
		if (!post) {
			const error = new Error('No post found');
			error.code = 404;
			throw error;
		}
		if (post.creator._id.toString() !== req.userId.toString()) {
			const error = new Error('Not authorized');
			error.code = 403;
			throw error;
		}
		const errors = [];
		if (!validator.isLength(postInput.title, { min: 3 })) {
			errors.push({ message: 'Title is too short' });
		}
		if (!validator.isLength(postInput.content, { min: 5 })) {
			errors.push({ message: 'Content is too short' });
		}
		if (errors.length > 0) {
			const error = new Error('Invalid input.');
			error.data = errors;
			throw error;
		}
		post.title = postInput.title;
		post.content = postInput.content;
		if (postInput.imageUrl !== 'undefined') {
			post.imageUrl = postInput.imageUrl;
		}
		const updatedPost = await post.save();
		return {
			...updatedPost._doc,
			_id: updatedPost._id.toString(),
			createdAt: updatedPost.createdAt.toISOString(),
			updatedAt: updatedPost.updatedAt.toISOString(),
		};
	},
	deletePost: async function ({ id }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}
		const post = await Post.findById(id);
		if (!post) {
			const error = new Error('No post found');
			error.code = 404;
			throw error;
		}
		if (post.creator.toString() !== req.userId.toString()) {
			const error = new Error('Not authorized');
			error.code = 403;
			throw error;
		}
		clearImage(post.imageUrl);
		await Post.findByIdAndRemove(id);
		const user = await User.findById(req.userId);
		user.posts.pull(id);
		await user.save();
		return true;
	},

	user: async function (args, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}
		const user = await User.findById(req.userId);
		return {
			...user._doc,
			_id: user._id.toString(),
		};
	},

	updateStatus: async function ({ statusInput }, req) {
		if (!req.isAuth) {
			const error = new Error('Not authenticated');
			error.code = 401;
			throw error;
		}
		const user = await User.findById(req.userId);
		user.status = statusInput;
		await user.save();
		return user;
	},
};
