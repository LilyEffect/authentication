const Authentication = require('./controllers/authentication')
const passportService = require('./services/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', { session: false });

module.exports = function(app) {
  app.get('/profile', requireAuth, function(req, res) {
    res.send({ authroized: true });
  });

  app.post('/signup', Authentication.signup);

  app.post('/login', requireSignin, Authentication.signin);
}
