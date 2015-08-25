
var utile = require('utile'),
    tools = require('./tools'),
    debug = require('debug')('turnkey'),
    pass = require('pwd'),
    keygrip = require('keygrip'),
    proto = module.exports = exports = {};

proto.launch = function(opts) {
  var cfg = this.config = utile.mixin(this.config || {}, opts || {}),
      self = this,
      hasCors = !!cfg.cors,
      cors = tools.createCors(cfg.cors),
      err = 0;

  // Required Options ----------------------------------------------------------
  if (!cfg.router) err++, cfg.logger.error('turnkey | no `router`');
  if (!cfg.deserialize) err++, cfg.logger.error('turnkey | no `deserialize` fn');
  if (!cfg.serialize) err++, cfg.logger.error('turnkey | no `serialize` fn');
  if (!cfg.findUser) err++, cfg.logger.error('turnkey | no `findUser` fn');
  if (!cfg.model) err++, cfg.logger.error('turnkey | no `model`');
  if (err) return cfg.logger.warn('turnkey | not starting (%d errors)', err);

  // Configure Model -----------------------------------------------------------
  cfg.model.schema.add({
    turnkey: {
      password: {
        salt: String,
        hash: String
      },
      verification: {
        code: {
          type: String,
          default: cfg.codeMaker
        },
        verified: {
          type: Boolean,
          default: cfg.verificationOn ? false : true
        }
      },
      forgot: {
        code: String,
        date: Date
      }
    }
  });

  // Keygrip options -----------------------------------------------------------

  this.keys = keygrip(cfg.authKeys || ['unused']);

  // Pass options --------------------------------------------------------------

  pass.iterations(cfg.hashIterations);
  pass.length(cfg.hashLength);

  // Middleware ----------------------------------------------------------------

  cfg.router.use(function(req, res, next) {
    var token = req.session.usertoken,
        turnkeyauth = req.headers['turnkey-auth'];

    if (turnkeyauth && cfg.authKeys) {
      try {
        turnkeyauth = JSON.parse(
          new Buffer(turnkeyauth, 'base64').toString('utf8')
        ) || {};

        if (turnkeyauth.id &&
            self.keys.verify(turnkeyauth.id, turnkeyauth.token)) {
          token = turnkeyauth.id;
        }
      } catch (e) { }

    }

    if (!token) return next(), debug('No user token');

    debug('user token: %s', token);

    cfg.deserialize(token, function(err, user) {
      if (err) return cfg.logger.error('turnkey | deserializing user: %s', err);
      debug('user is logged in: %j', user);
      req.user = user;
      if (user && user.hasOwnProperty('turnkey')) {
        Object.defineProperty(user, 'turnkey', {
          enumerable: false,
          configurable: true,
          writable: false,
          value: user.turnkey
        });
      }
      next();
    });

  });

  // Routes --------------------------------------------------------------------
  if (hasCors) cfg.router.options('/turnkey/login', cors);

  cfg.router.post('/turnkey/login', cors, function(req, res) {
    var body = req.body,
        password = body.password;

    debug('login: %j', body);

    cfg.findUser(body, function(e, user) {
      var tk = user && user.turnkey,
          v = user && user.turnkey && user.turnkey.verification &&
              user.turnkey.verification.verified,
          tkpw = tk && tk.password;

      if (e) {
        res.json(self.errorObject(3, 'invalid password'));
        return cfg.logger.error('turnkey | error finding user: %s', e);
      }

      if (!user) return res.json(self.errorObject(3, 'invalid password')),
                        debug('no user found: %j', body);

      if (cfg.verificationOn && !v) {
        debug('not verified: %j', body);
        return res.json(self.errorObject(10, 'not verified'));
      }

      if (!tk || !tkpw)
        return res.json(self.errorObject(3, 'invalid password')),
               debug('no turnkey object: %j', user);

      debug('Found user. Turnkey object: %j', tk);

      self.verify(password, tkpw, function(valid) {
        var data;
        if (valid) {
          cfg.serialize(user, function(e, id) {
            if (e) cfg.logger.error('turnkey | error serializing user: %s', e);
            if (e || !id) return res.json({ error: 'failed to authenticate' });
            req.session.usertoken = id;
            data = {
              id: id,
              token: self.keys.sign(String(id))
            };
            res.json({
              error: null,
              data: new Buffer(JSON.stringify(data), 'utf8').toString('base64')
            });
          });
        } else res.json({ error: 'failed to authenticate' });
      });
    });
  });

  if (hasCors) cfg.router.options('/turnkey/logout', cors);

  cfg.router.get('/turnkey/logout', cors, function(req, res) {
    req.session.usertoken = null;
    res.redirect(cfg.logoutRedirect());
  });

  if (!cfg.forgotMailer) return debug('no forgot mailer set');

  if (hasCors) cfg.router.options('/turnkey/forgot', cors);

  cfg.router.post('/turnkey/forgot', cors, function(req, res) {
    var body = req.body;

    cfg.findUser(body, function(e, user) {
      var id = user && user._id,
          code = cfg.codeMaker(),
          v = user && user.turnkey && user.turnkey.verification &&
              user.turnkey.verification.verified,
          update = {
            'turnkey.forgot.code': code,
            'turnkey.forgot.date': new Date()
          };

      if (e) {
        res.json(self.errorObject(7, 'invalid user'));
        return cfg.logger.error('turnkey | error finding user: %s', e);
      }

      if (!user || !id) {
        debug('no user found: %j', body);
        return res.json(self.errorObject(7, 'invalid user'));
      }

      if (cfg.verificationOn && !v) {
        debug('not verified: %j', body);
        return res.json(self.errorObject(10, 'not verified'));
      }

      debug('forgot user code: %j', update);
      cfg.model.findByIdAndUpdate(id, update, function(e, user) {
        if (e) {
          res.json(self.errorObject(7, 'invalid user'));
          return cfg.logger.error('turnkey | error updating user: %s', e);
        }

        if (!user) {
          res.json(self.errorObject(7, 'invalid user'));
          return debug('did not update user on forgot');
        }

        cfg.forgotMailer.call(
            { request: req, response: res },
            user, code, function(e) {
          if (e) {
            res.json(self.errorObject(7, 'invalid user'));
            return cfg.logger.error('turnkey | error mailing user: %s', e);
          }
          res.json({ data: true });
        })
      });
    });
  });

  if (hasCors) cfg.router.options('/turnkey/reset', cors);

  cfg.router.put('/turnkey/reset', cors, self.createPassword(),
                 cors, function(req, res) {
    var body = req && req.body,
        code = body && body.code,
        turnkey = body && body['turnkey.password'],
        time = new Date().getTime() - cfg.forgotLimit,
        query = {
          'turnkey.forgot.code': code,
          'turnkey.forgot.date': { $gte: new Date(time) }
        },
        update = { "turnkey.password": turnkey, "turnkey.forgot": {} };

    if (!code) {
      res.json(self.errorObject(8, 'no code provided'));
      return debug('no code provided');
    }

    debug('resetting password.\n    query-> %j\n    update-> %j',
          query, update);

    cfg.model.update(query, update, function(e, d) {
      if (e || !d) {
        res.json(self.errorObject(9, 'invalid code'));
        return debug('invalid code (error? %s): %j', !!e, e || d);
      }

      res.json({ data: true });
    });

  });

  if (hasCors) cfg.router.options('/turnkey/verify/:code', cors);

  cfg.router.get('/turnkey/verify/:code', cors, function(req, res) {
    var q = {
          'turnkey.verification.verified': false,
          'turnkey.verification.code': req.params.code
        },
        u = {
          'turnkey.verification.verified': true,
          'turnkey.verification.code': req.params.code
        },
        json = req.query && req.query.json;

    cfg.model.findOneAndUpdate(q, u, function(e, user) {
      var success = !e && user,
          query = '?turnkey-verification=' + (success ? 'success' : 'failure'),
          data = {
            id: cfg.authKeys && String(user && user._id),
            token: cfg.authKeys && self.keys.sign(String(user && user._id))
          },
          dataStr = new Buffer(JSON.stringify(data), 'utf8').toString('base64');

      if (!success || !cfg.loginOnVerify) {
        if (json) return res.send({ error: success ? null : 'wrong code',
                                    data: success ? true : false });
        return res.redirect(cfg.verifyRedirect + query);
      }

      cfg.serialize(user, function(e, id) {
        if (e) cfg.logger.error('turnkey | error serializing user: %s', e);
        if (e || !id) query = '?turnkey-verification=failure';
        if (!e && id) req.session.usertoken = id;
        if (json) return res.send({ error: success ? null : 'wrong code',
                                    data: success ? dataStr : false });
        res.redirect(cfg.verifyRedirect + query);
      });
    });
  });

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

proto.createPassword = function() {
  var self = this;

  return function (req, res, next) {
    var body = req.body,
        pw = body && body.password;

    if (!pw || !pw.length || pw.length < self.config.minLength) {
      return res.json(self.errorObject(1, 'invalid password')),
             debug('invalid password: %s', pw);
    }

    delete body.password;  // remove from body object

    // protect
    if (body.turnkey) delete body.turnkey;
    if (body['turnkey.verification']) delete body['turnkey.verification'];
    if (body['turnkey.verification.verified'])
      delete body['turnkey.verification.verified'];

    debug('making password object for: %s', pw);
    self.makeHash(pw, function(e, salt, hash) {
      if (e || !salt || !hash) {
        debug('failed to make hash');
        return res.json(self.errorObject(2, 'failed to make password'));
      }

      body['turnkey.password'] = { salt: salt, hash: hash };
      debug('password object made: %j', body['turnkey.password']);
      next();
    });
  }
}

proto.updatePassword = function() {
  var self = this;

  return function (req, res, next) {
    var body = req.body,
        user = req.user,
        tk = user && user.turnkey,
        tkpw = tk && tk.password,
        pw = body && body.password,
        old = body && body.oldPassword || body.old_password;

    if (!pw) return next();

    if (!pw.length || pw.length < self.config.minLength) {
      debug('invalid password: %s', pw);
      return res.json(self.errorObject(1, 'invalid password'));
    }

    if (!old) {
      debug('no oldPassword');
      return res.json(self.errorObject(6, 'invalid oldPassword'));
    }

    if (!tkpw) {
      debug('must be logged in');
      return res.json(self.errorObject(6, 'invalid oldPassword'));
    }

    self.verify(old, tkpw, function(valid) {
      if (!valid) {
        debug('invalid old password');
        return res.json(self.errorObject(6, 'invalid oldPassword'));
      }

      delete body.password;  // remove from body object
      delete body.oldPassword;  // remove from body object
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

proto.checkResend = function(cb, modify) {
  var self = this,
      cfg = this.config;

  return function(req, res, next) {
    var k;

    cfg.findUser(req.body, function(e, d) {
      if (e) return res.json(self.errorObject(-1, 'unknown'));
      if (!d) return next();  // No user like this already
      if (!(d && d.turnkey && d.turnkey.verification &&
            !d.turnkey.verification.verified)) return next();  // verified

      // We have an unverified user
      debug('Unverified user. Will fake that we created it.');
      cb && cb(d);

      // Modify for response
      delete d.turnkey;
      if (modify) d = modify(d);
      res.json({ data: d });
    });
  }
}
