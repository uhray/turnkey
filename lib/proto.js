
var utile = require('utile'),
    tools = require('./tools'),
    debug = require('debug')('turnkey'),
    pass = require('pwd'),
    proto = module.exports = exports = {};

proto.launch = function(opts) {
  var cfg = this.config = utile.mixin(this.config || {}, opts || {}),
      self = this,
      err = 0;

  // Required Options ----------------------------------------------------------
  if (!cfg.router) err++, cfg.logger.error('turnkey | no `router`');
  if (!cfg.deserialize) err++, cfg.logger.error('turnkey | no `deserialize` fn');
  if (!cfg.serialize) err++, cfg.logger.error('turnkey | no `serialize` fn');
  if (!cfg.find_user) err++, cfg.logger.error('turnkey | no `find_user` fn');
  if (!cfg.model) err++, cfg.logger.error('turnkey | no `model`');
  if (err) return cfg.logger.warn('turnkey | not starting (%d errors)', err);

  // Configure Model -----------------------------------------------------------
  cfg.model.schema.add({
    turnkey: {
      password: {
        salt: String,
        hash: String
      }
      /*
      change_email: {
        code:     { type: String },
        email:    { type: String }
      },
      code: String,
      */
    }
  });

  // Pass options --------------------------------------------------------------

  pass.iterations(cfg.hash_iterations);
  pass.length(cfg.hash_length);

  // Middleware ----------------------------------------------------------------

  cfg.router.use(function(req, res, next) {
    var token = req.session.usertoken;
    if (!token) return next();

    cfg.deserialize(token, function(err, user) {
      if (err) return cfg.logger.error('turnkey | deserializing user: %s', err);
      req.user = user;
      next();
    });

  });

  // Routes --------------------------------------------------------------------
  cfg.router.post('/turnkey/login', function(req, res) {
    var self = this,
        body = req.body,
        password = body.password;

    cfg.find_user(body, function(e, user) {
      if (e) return res.json({ error: 'error finding user' }),
                    cfg.logger.error('turnkey | error finding user: %s', e);
      if (!d) return res.json({ error: 'failed to authenticate' });

      self.verify(password, user.turnkey && user.turnkey.password,
                  function(valid) {
        if (valid) {
          cfg.serialize(user, function(e, id){
            if (e) cfg.logger.error('turnkey | error serializing user: %s', e);
            if (e || !d) return res.json({ error: 'failed to authenticate' });
            req.session.usertoken = id;
            res.json({ error: null, data: d });
          });
        } else res.json({ error: 'failed to authenticate' });
      });
    });


        //email = (body && body.email && body.email.toLowerCase()) || '',
        //password = (body && body.password) || '';

    models.users.findOne({ email: email, 'booleans.deleted' : false },
                         function(e, d) {
      if (e) return res.json({ error: 'error with db' });
      if (!d) return res.json({ error: 'failed to authenticate' });
      verify(password, d.password, function(valid) {
        if (valid) {
          req.session.usertoken = String(d._id);
          res.json({ error: null, data: d });
        } else {
          res.json({ error: 'failed to authenticate', data: null });
        }
      });
    });
  });

  cfg.router.get('/turnkey/logout', function(req, res) {
    req.session.usertoken = null;
    res.redirect('/');
  });

  // TODO: reset password & change email
  //    --> should these really be a part of turnkey? I guess so but they are
  //        slightly unrelated
}

proto.makeHash = function(pwd, salt, fn) {
  return pass.hash.apply(pass, arguments);
};

proto.verify = function(pw, auth, cb) {
  this.makeHash(pw, auth && auth.salt, function(e, hash) {
    cb(hash == (auth && auth.hash));
  });
};

proto.makePassword = function(n) {
  var text = '',
      possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'  +
                 'abcdefghijklmnopqrstuvwxyz0123456789';

  for( var i=0; i < (n || 5); i++ )
    text += possible.charAt(Math.floor(Math.random() * possible.length));

  return text;
};

