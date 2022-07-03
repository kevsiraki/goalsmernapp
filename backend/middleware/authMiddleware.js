const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

const protect = asyncHandler(async(req, res, next) => {
	let token
	
	if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
		try {
			//get token from header
			token = req.headers.authorization.split(' ')[1] //[0]bearer [1]token (split by space, take the 1 index (token))
			
			//verify token
			const decoded = jwt.verify(token,process.env.JWT_SECRET)
			
			//get user from the token
			req.user = await User.findById(decoded.id).select('-password')
			
			next() //next piece of middleware called
		} catch(error) {
			console.log(error)
			res.status(401) //if something goes wrong
			throw new Error('Not authorized')
		}
	}
	if(!token) {
		res.status(401) //if no token at all
		throw new Error('Not authorized, no token')
	}
})

module.exports = { protect }