const { validationResult } = require('express-validator');
const path = require('path');
const fs = require('fs');
const Post = require('../models/post');
const User = require('../models/user');
const io = require('../socket');

exports.getPosts = async (req, res, next) => {
	const currentPage = req.query.page || 1;
	const perPage = 2;
	try {
		const totalItems = await Post.find().countDocuments();
		const posts = await Post.find()
			.populate('creator')
			.sort({ createdAt: -1 })
			.skip((currentPage - 1) * perPage)
			.limit(perPage);
		res.status(200).json({
			message: 'Fetched posts successfully',
			posts: posts,
			totalItems: totalItems,
		});
	} catch (err) {
		if (!err.statusCode) {
			err.statusCode = 500;
		}
		next(err);
	}
};

exports.createPost = async (req, res, next) => {
	const title = req.body.title;
	const content = req.body.content;
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		const error = new Error(
			'Validation failed, entered data is incorrect.'
		);
		error.statusCode = 422;
		throw error;
	}
	if (!req.file) {
		const error = new Error('No image provided');
		error.statusCode = 422;
		throw error;
	}
	const imageUrl = req.file.path;
	const post = new Post({
		title: title,
		content: content,
		imageUrl: imageUrl,
		creator: req.userId,
	});
	try {
		const savedPost = await post.save();
		const user = await User.findById(req.userId);
		creator = user;
		user.posts.push(savedPost);
		await user.save();
		io.getIO().emit('posts', {
			action: 'create',
			post: {
				...post._doc,
				creator: { _id: req.userId, name: user.name },
			},
		});
		res.status(201).json({
			message: 'Post created successfully',
			post: savedPost,
			creator: {
				_id: user._id,
				name: user.name,
			},
		});
	} catch (err) {
		if (!err.statusCode) {
			err.statusCode = 500;
		}
		next(err);
	}
};

exports.getPost = async (req, res, next) => {
	const postId = req.params.postId;
	try {
		const post = await Post.findById(postId);
		if (post) {
			if (!post) {
				const error = new Error('Could not find posts.');
				error.statusCode = 404;
				throw error;
			}
			res.status(200).json({
				message: 'Post fetched',
				post: post,
			});
		}
	} catch (err) {
		if (!err.statusCode) {
			err.statusCode = 500;
		}
		next(err);
	}
};

exports.updatePost = async (req, res, next) => {
	const postId = req.params.postId;
	const title = req.body.title;
	const content = req.body.content;
	let imageUrl = req.body.image;
	if (req.file) {
		imageUrl = req.file.path;
	}
	if (!imageUrl) {
		const error = new Error('No file picked!');
		error.statusCode = 422;
		throw error;
	}
	try {
		const post = await Post.findById(postId).populate('creator');
		if (!post) {
			const error = new Error('Could not find post');
			error.statusCode = 404;
			throw error;
		}
		if (post.creator._id.toString() !== req.userId) {
			const error = new Error('Not authorized');
			error.statusCode = 403;
			throw error;
		}
		if (imageUrl !== post.imageUrl) {
			clearImage(post.imageUrl);
		}
		post.title = title;
		post.content = content;
		post.imageUrl = imageUrl;
		const savedPost = await post.save();
		io.getIO().emit('posts', { action: 'update', post: savedPost });
		res.status(200).json({
			message: 'Edited post successfully',
			post: savedPost,
		});
	} catch (err) {
		if (!err.statusCode) {
			err.statusCode = 500;
		}
		next(err);
	}
};

exports.deletePost = async (req, res, next) => {
	const postId = req.params.postId;
	const post = await Post.findById(postId);
	if (!post) {
		const error = new Error('Could not find post');
		error.statusCode = 404;
		throw error;
	}
	if (post.creator.toString() !== req.userId) {
		const error = new Error('Not authorized');
		error.statusCode = 403;
		throw error;
	}
	clearImage(post.imageUrl);
	try {
		await Post.findByIdAndRemove(postId);
		const user = await User.findById(req.userId);
		user.posts.pull(postId);
		await user.save();
		io.getIO().emit('posts', { action: 'delete', post: postId });
		res.status(200).json({
			message: 'Deleted Post',
		});
	} catch (err) {
		if (!err.statusCode) {
			err.statusCode = 500;
		}
		next(err);
	}
};

exports.getStatus = async (req, res, next) => {
	try {
		const user = await User.findById(req.userId);

		if (!user) {
			const error = new Error('Not Authorized');
			error.statusCode = 403;
			throw error;
		}
		res.status(200).json({
			message: 'fetched status successfully',
			status: user.status,
		});
	} catch (err) {
		if (!err.statusCode) {
			err.statusCode = 500;
		}
		next(err);
	}
};

exports.updateStatus = async (req, res, next) => {
	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		const error = new Error(
			'Validation failed, entered data is incorrect.'
		);
		error.statusCode = 422;
		throw error;
	}
	const status = req.body.status;
	try {
		const user = await User.findById(req.userId);
		if (!user) {
			const error = new Error('Not Authorized');
			error.statusCode = 403;
			throw error;
		}

		user.status = status;
		const savedUser = await user.save();
		res.status(200).json({
			message: 'Updated status successfully',
			status: savedUser.status,
		});
	} catch (err) {
		if (!err.statusCode) {
			err.statusCode = 500;
		}
		next(err);
	}
};

const clearImage = (filePath) => {
	filePath = path.join(__dirname, '..', filePath);
	fs.unlink(filePath, (err) => console.log(err));
};
