const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');
const validator = require('validator');

function generateUserToken(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  // By now, user has already had their email/password authorized
  // Now, assign them a token
  res.send({ token: generateUserToken(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if(!email || !password) {
    return res.status(422).send({ error: 'You must provide both an email and a password'});
  }

  if (!validator.isEmail(email)) {
    return res.status(422).send({ error: "you must supply a valid email" });
  }

  // See if a user with the given email already exists
  User.findOne({email}, function(err, user) {
    // internal search error
    if (err) { return next(err); }


    // User already exists
    if (user) {
      return res.status(422).send({ error: 'Email is in use' });
    }

    // If user is a new user, create and save user record
    const newUser = new User({ email, password });

    newUser.save(function(err) {
      if (err) { return next(err); }

      // Respond to request
      res.json({ token: generateUserToken(newUser) });
    });
  });
}
