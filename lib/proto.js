
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

    if (!token) return next(), debug('No user token');

    debug('user token: %s', token);

    cfg.deserialize(token, function(err, user) {
      if (err) return cfg.logger.error('turnkey | deserializing user: %s', err);
      debug('user is logged in: %j', user);
      req.user = user;
      next();
    });

  });

  // Routes --------------------------------------------------------------------
  cfg.router.post('/turnkey/login', function(req, res) {
    var body = req.body,
        password = body.password;

    debug('login: %j', body);

    cfg.find_user(body, function(e, user) {
      var tk = user && user.turnkey,
          tkpw = tk && tk.password;
      if (e) return res.json({ error: 'error finding user' }),
                    cfg.logger.error('turnkey | error finding user: %s', e);
      if (!user) return res.json(self.errorObject(3, 'invalid password')),
                        debug('no user found: %j', body);
      if (!tk || !tkpw)
        return res.json(self.errorObject(3, 'invalid password')),
               debug('no turnkey object: %j', user);

      debug('Found user. Turnkey object: %j', tk);

      self.verify(password, tkpw, function(valid) {
        if (valid) {
          cfg.serialize(user, function(e, id) {
            if (e) cfg.logger.error('turnkey | error serializing user: %s', e);
            if (e || !id) return res.json({ error: 'failed to authenticate' });
            req.session.usertoken = id;
            res.json({ error: null, data: id });
          });
        } else res.json({ error: 'failed to authenticate' });
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

proto.errorObject = function(code, msg) {
  return { error: { msg: msg, code: code, source: 'turnkey' } };
}

proto.createPassword = function(minLength) {
  var minLength = minLength || 8,
      self = this;

  return function (req, res, next) {
    var body = req.body,
        pw = body && body.password;

    if (!pw || !pw.length || pw.length < minLength) {
      return res.json(self.errorObject(1, 'invalid password')),
             debug('invalid password: %s', pw);
    }

    delete body.password;  // remove from body object

    debug('making password object for: %s', pw);
    self.makeHash(pw, function(e, salt, hash) {
      if (e || !salt || !hash) {
        debug('failed to make hash');
        return res.json(self.errorObject(2, 'failed to make password'));
      }

      body.turnkey = { password: { salt: salt, hash: hash } };
      debug('password object made: %j', body.turnkey.password);
      next();
    });
  }
}

proto.updatePassword = function(minLength) {
  var minLength = minLength || 8,
      self = this;

  return function (req, res, next) {
    var body = req.body,
        user = req.user,
        tk = user && user.turnkey,
        tkpw = tk && tk.password,
        pw = body && body.password,
        old = body && body.old_password;

    if (!pw) return next();

    if (!pw.length || pw.length < minLength) {
      debug('invalid password: %s', pw);
      return res.json(self.errorObject(1, 'invalid password'));
    }

    if (!old) {
      debug('no old_password');
      return res.json(self.errorObject(6, 'invalid old_password'));
    }

    if (!tkpw) {
      debug('must be logged in');
      return res.json(self.errorObject(6, 'invalid old_password'));
    }

    self.verify(old, tkpw, function(valid) {
      if (!valid) {
        debug('invalid old password');
        return res.json(self.errorObject(6, 'invalid old_password'));
      }

      delete body.password;  // remove from body object
      delete body.old_password;  // remove from body object

      debug('making password object for: %s', pw);
      self.makeHash(pw, function(e, salt, hash) {
        if (e || !salt || !hash) {
          debug('failed to make hash');
          return res.json(self.errorObject(2, 'failed to make password'));
        }

        body.turnkey = { password: { salt: salt, hash: hash } };
        debug('password object made: %j', body.turnkey.password);
        next();
      });
    });


  }
}

// loggedIn - make sure a user is logged in
//
// The returns a crud middleware function to check if the user is logged in.
// If there are any vals, structured as an object of key-value, then in makes
// sure this user has the correct credentials.
//
// turnkey.loggedIn({ role: 'admin' })
//    --> makes sure the user is an admin
// turnkey.loggedIn({ role: [ 'admin', 'root' ] })
//    --> makes sure the user is an admin or root
proto.loggedIn = function(vals) {
  var self = this;
  return function(req, res, next) {
    var k;
    if (req && req.user && req.user._id) {
      for (k in vals) {
        if (vals[k] instanceof Array) {
          if (!~vals[k].indexOf(req.user[k])) {
            debug('unauthorized for %s in %j: %j', k, vals[k], req.user);
            return res.json(self.errorObject(4, 'unauthorized'));
          }
        } else if (vals[k] != req.user[k]) {
          debug('unauthorized for %s=%s: %j', k, vals[k], req.user);
          return res.json(self.errorObject(4, 'unauthorized'));
        }
      }

      return next();
    }
    else return res.json(self.errorObject(4, 'unauthorized'));
  }
}
