
var utile = require('utile'),
    tools = require('./tools'),
    debug = require('debug')('turnkey'),
    pass = require('./pwd'),
    keygrip = require('keygrip'),
    assert = require('assert'),
    uuid = require('uuid'),
    EventEmitter = require('events').EventEmitter,
    proto = module.exports = exports = {};

utile.mixin(proto, EventEmitter.prototype);

proto.launch = function(opts) {
  var cfg = this.config = utile.mixin(this.config || {}, opts || {}),
      self = this,
      hasCors = !!cfg.cors,
      cors = tools.createCors(cfg.cors),
      err = 0;

  // Required Options ----------------------------------------------------------
  assert(cfg.router, 'turnkey | no `router`');
  assert(cfg.deserialize, 'turnkey | no `deserialize` fn');
  assert(cfg.serialize, 'turnkey | no `serialize` fn');
  assert(cfg.findUser, 'turnkey | no `findUser` fn');
  assert(cfg.model, 'turnkey | no `model`');

  // Configure Model -----------------------------------------------------------
  cfg.model.schema.add({
    turnkey: {
      password: String,
      uuid: { type: String, default: uuid.v4, index: true },
      verification: {
        code: {
          type: String,
          default: cfg.codeMaker,
        },
        verified: {
          type: Boolean,
          default: cfg.verificationOn ? false : true
        }
      },
      codeAuth: {
        maxTime: { type: Date, default: new Date() },
        code: {
          type: String,
          default: cfg.codeMaker,
          index: !!cfg.codeAuth
        }
      },
      forgot: {
        code: String,
        date: Date
      },
      social: {
        id: String,
        network: String,
        token: String,
        expiration: Date
      }
    }
  });

  // Keygrip options -----------------------------------------------------------

  this.keys = keygrip(cfg.authKeys || ['unused']);

  // Pass options --------------------------------------------------------------

  pass.iterations(cfg.hashIterations);

  // Middleware ----------------------------------------------------------------

  cfg.router.use(this.turnkeyAuthMW());
  cfg.router.use(this.turnkeyMockMW());

  // Routes --------------------------------------------------------------------
  if (hasCors) cfg.router.options('/turnkey/login', cors);

  cfg.router.post('/turnkey/login', cors, function(req, res) {
    debug('login: %j', req.body);
    self.authenticateUser(req.body, req, function(e, data) {
      if (e) res.json(e)
      else res.json({ error: null, data: data });
    });
  });

  if (hasCors) cfg.router.options('/turnkey/logout', cors);

  cfg.router.get('/turnkey/logout', cors, function(req, res) {
    var mockToken = req.session.mockUserToken;

    if (cfg.mockUser && mockToken) req.session.mockUserToken = null;
    else req.session.usertoken = null;
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
        turnkey = body && body.turnkey && body.turnkey.password,
        lastUUID = body && body.turnkey && body.turnkey.uuid,
        time = new Date().getTime() - cfg.forgotLimit,
        query = {
          'turnkey.forgot.code': code,
          'turnkey.forgot.date': { $gte: new Date(time) }
        },
        update = {
          turnkey: {
            password: turnkey,
            forgot: {},
            uuid: lastUUID || uuid.v4(),
            verification: { verified: true }
          }
        };

    if (!code) {
      res.json(self.errorObject(8, 'no code provided'));
      return debug('no code provided');
    }

    debug('resetting password.\n    query-> %j\n    update-> %j',
          query, update);

    cfg.model.update(query, update, function(e, d) {
      if (e || !d || !d.nModified) {
        res.json(self.errorObject(9, 'invalid code'));
        return debug('invalid code (error? %s): %j', !!e, e || d);
      }

      res.json({ data: true });
    });

  });

  if (cfg.codeAuth) {

    if (hasCors) cfg.router.options('/turnkey/codeAuth', cors);

    cfg.router.post('/turnkey/codeAuth', cors, function(req, res) {
      cfg.findUser(req.body, function(e, u) {
        if (e || !u) return done('user not found');

        var code = cfg.codeMaker(),
            time = new Date(Date.now() + cfg.codeAuthLimit),
            update = {
              $set: {
                'turnkey.codeAuth.code': code,
                'turnkey.codeAuth.maxTime': time
              }
            };

        cfg.model.findByIdAndUpdate(u._id, update).lean().exec(function(e, u) {
          if (e) return done('user not found');

          cfg.codeAuth(u, code, function(e, d) {
            done(e, e ? null : 'message sent');
          });
        });

      });

      function done(e, d) {
        res.json({ error: e, data: d });
      }
    });

    if (hasCors) cfg.router.options('/turnkey/codeAuth/:authKey', cors);

    cfg.router.get('/turnkey/codeAuth/:authKey', cors, function(req, res) {
      cfg.model.findOne({
        'turnkey.codeAuth.code': req.params.authKey,
        'turnkey.codeAuth.maxTime': { $gte: new Date() }
      }).lean().exec(function(e, user) {
        if (e || !user) return done('Invalid code');

        cfg.serialize(user, function(e, id) {
          var data = {
                id: cfg.authKeys && id,
                token: cfg.authKeys && self.keys.sign(id)
              },
              dataStr = new Buffer(JSON.stringify(data), 'utf8')
                            .toString('base64');

          done(null, dataStr);

          // Override current
          cfg.model.findByIdAndUpdate(u._id, {
            'turnkey.codeAuth.code': tools.uuid()
          }).lean().exec(function() { });
        });

      });

      function done(e, d) {
        res.json({ error: e, data: d });
      }
    });
  }

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

    cfg.model.findOneAndUpdate(q, u).lean().exec(function(e, user) {
      var success = !e && user,
          query = '?turnkey-verification=' + (success ? 'success' : 'failure');

      // verify callback function
      if (success) self.emit('verification', user);

      if (!success || !cfg.loginOnVerify) {
        if (json) return res.send({ error: success ? null : 'wrong code',
                                    data: success ? true : false });
        return res.redirect(cfg.verifyRedirect + query);
      }

      cfg.serialize(user, function(e, id) {
        var data = {
              id: cfg.authKeys && id,
              token: cfg.authKeys && self.keys.sign(id)
            },
            dataStr = new Buffer(JSON.stringify(data), 'utf8')
                            .toString('base64');

        if (e) cfg.logger.error('turnkey | error serializing user: %s', e);
        if (e || !id) query = '?turnkey-verification=failure';
        if (!e && id) req.session.usertoken = id;
        if (json) return res.send({ error: success ? null : 'wrong code',
                                    data: success ? dataStr : false });
        res.redirect(cfg.verifyRedirect + query);
      });
    });
  });

  if (hasCors) cfg.router.options('/turnkey/mockUser/:user', cors);

  cfg.router.get('/turnkey/mockUser/:user', cors, function(req, res) {
    var u = req.user,
        query = {};

    // make sure this is allowed
    if (!cfg.mockUser) return res.send('unauthorized');
    if (!u) return res.send('unauthorized');
    if (!cfg.mockUserAuth(u)) return res.send('unauthorized');

    // find new user
    query[cfg.mockUserKey] = req.params.user;
    cfg.findUser(query, function(e, mockUser) {
      if (e || !mockUser) return res.send('unauthorized');
      cfg.serialize(mockUser, function(e, id) {
        var data;

        if (e) cfg.logger.error('turnkey | error serializing user: %s', e);
        if (e || !id) return res.send('unauthorized');
        req.session.mockUserToken = id;

        if (req.query.json) {
          data = {
            id: id,
            token: self.keys.sign(String(id))
          };
          data = new Buffer(JSON.stringify(data), 'utf8').toString('base64');
          res.json({ data: data, error: null });
        } else res.redirect('/');
      });
    });
  });

  if (cfg.socialAuth) {
    if (hasCors) cfg.router.options('/turnkey/socialAuth', cors);

    cfg.router.post('/turnkey/socialAuth', cors, function(req, res) {
      var d = req.body,
          secret;

      self.authenticateSocial(d, req, function(e, d) {
        if (e) res.json({ error: e })
        else res.json({ error: null, data: d });
      });
    });
  }
}

proto.authenticateSocial = function(d, req, cb) {
  var cfg = this.config,
      self = this,
      secret;

  if (!d) return cb('invalid data');
  if (!d.auth) return cb('invalid data');
  if (!d.auth.clientId) return cb('invalid data');
  if (!d.auth.id) return cb('invalid data');
  if (!d.auth.network) return cb('invalid data');
  if (!d.auth.token) return cb('invalid data');

  secret = cfg.socialSecrets[d.auth.network];
  if (!secret) return cb('network not configured');

  tools.verifyNetwork(
    d.auth.id,
    d.auth.network,
    d.auth.token,
    d.auth.clientId,
    secret,
    function(verified) {
      var socialInfo = {
            id: String(d.auth.id),
            network: String(d.auth.network),
            token: String(d.auth.token),
            expiration: String(d.auth.expiration)
          };

      if (!verified) return cb('unauthorized');

      cfg.model.findOneAndUpdate({
        'turnkey.social.id': String(d.auth.id),
        'turnkey.social.network': String(d.auth.network)
      }, { 'turnkey.social': socialInfo }).lean().exec(function(e, user) {
        if (e || !user) {
          debug('social - no user found');

          // if there isn't a process for creating a user, don't do it
          if (!d.create || !cfg.socialCreate)
            return cb('unauthorized');

          debug('creating social user');
          d.create.turnkey = {
            verification: { verified: true },
            social: socialInfo
          };

          cfg.socialCreate(d.create, function(e, d) {
            if (e) cb({ error: e });
            else if (!d) cb('unauthorized');
            else isAuthed(d);
          });
        } else {
          debug('social - user %s found', user._id);

          if (!d.create || !cfg.socialUpdate) return isAuthed(user);

          d.create.turnkey = {
            verification: { verified: true },
            social: socialInfo
          };

          cfg.socialUpdate(user, d.create, function(e, u) {
            if (u) user = u;
            if (e) return cb(e);
            isAuthed(user);
          });
        }
      });
    }
  );

  function isAuthed(u) {
    debug('social - authenticated user %j', u);
    cfg.serialize(u, function(e, id) {
      var data;
      if (e) cfg.logger.error('turnkey | error serializing user: %s', e);
      if (e || !id) return cb({ error: 'failed to authenticate' });
      if (req) req.session.usertoken = id;
      data = {
        id: id,
        token: self.keys.sign(String(id))
      };
      cb(null, new Buffer(JSON.stringify(data), 'utf8').toString('base64'),
         data);
    });
  }
}

proto.authenticateUser = function(body, req, cb) {
  var password = body.password,
      cfg = this.config,
      self = this;

  cfg.findUser(body, function(e, user) {
    var tk = user && user.turnkey,
        v = user && user.turnkey && user.turnkey.verification &&
            user.turnkey.verification.verified,
        social = user && user.turnkey && user.turnkey.social,
        tkpw = tk && tk.password;

    if (e) {
      cfg.logger.error('turnkey | error finding user: %s', e);
      return cb(self.errorObject(3, 'invalid password'));
    }

    if (!user) {
      debug('no user found: %j', body);
      return cb(self.errorObject(3, 'invalid password'));
    }

    if (cfg.verificationOn && !v) {
      debug('not verified: %j', body);
      return cb(self.errorObject(10, 'not verified'));
    }

    if ((!tk || !tkpw) && social) {
      debug('no turnkey object: %j', user);
      return cb(self.errorObject(11, 'social auth', {
        network: (social && social.network)
      }));
    }

    if (!tk || !tkpw) {
      debug('no turnkey object: %j', user);
      return cb(self.errorObject(3, 'invalid password'));
    }

    debug('Found user. Turnkey object: %j', tk);

    self.verify(password, tkpw, function(valid) {
      var data;
      if (valid) {
        cfg.serialize(user, function(e, id) {
          if (e) cfg.logger.error('turnkey | error serializing user: %s', e);
          if (e || !id) return cb({ error: 'failed to authenticate' });

          if (req) req.session.usertoken = id;
          data = {
            id: id,
            token: self.keys.sign(String(id))
          };

          cb(null, new Buffer(JSON.stringify(data), 'utf8').toString('base64'),
             data);
        });
      } else cb({ error: 'failed to authenticate' });
    });
  });
}

proto.makeHash = function(p, fn) {
  return pass.hash.apply(p, arguments);
};

proto.verify = function(pw, auth, cb) {
  pass.compare(pw, auth, function(e, success) {
    cb(!e && success);
  });
};

proto.errorObject = function(code, msg, info) {
  return { error: { msg: msg, code: code, source: 'turnkey', info: info } };
}

proto.createPassword = function() {
  var self = this;

  return function(req, res, next) {
    var body = req.body,
        pw = body && body.password;

    if (!pw || !pw.length || pw.length < self.config.minLength) {
      return res.json(self.errorObject(1, 'invalid password')),
             debug('invalid password: %s', pw);
    }

    if (self.config.verifyPassword && !self.config.verifyPassword(pw)) {
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
    self.makeHash(pw, function(e, hashed) {
      if (e || !hashed) {
        debug('failed to make hash');
        return res.json(self.errorObject(2, 'failed to make password'));
      }

      if ('turnkey.password' in body) delete body['turnkey.password'];
      body.turnkey = { password: hashed };
      debug('password object made: %j', body['turnkey.password']);
      next();
    });
  }
}

proto.updatePassword = function(auth) {
  var self = this;

  auth = auth || function() { return false; }

  return function(req, res, next) {
    var body = req.body,
        user = req.user,
        tk = user && user.turnkey,
        tkpw = tk && tk.password,
        pw = body && body.password,
        // jscs:disable
        old = body && body.oldPassword || body.old_password;
        // jscs:enable

    if (!pw) return next();

    if (!pw.length || pw.length < self.config.minLength) {
      debug('invalid password: %s', pw);
      return res.json(self.errorObject(1, 'invalid password'));
    }

    if (self.config.verifyPassword && !self.config.verifyPassword(pw)) {
      return res.json(self.errorObject(1, 'invalid password')),
             debug('invalid password: %s', pw);
    }

    if (!auth.apply(this, arguments)) {
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

        doUpdate();
      });
    } else doUpdate();  // authed to update password

    function doUpdate() {
      delete body.password;  // remove from body object
      delete body.oldPassword;  // remove from body object
      // jscs:disable
      delete body.old_password;  // remove from body object
      // jscs:enable

      debug('making password object for: %s', pw);
      self.makeHash(pw, function(e, hashed) {
        if (e || !hashed) {
          debug('failed to make hash');
          return res.json(self.errorObject(2, 'failed to make password'));
        }

        body.turnkey = { password: hashed };
        debug('password object made: %j', body.turnkey.password);
        next();
      });
    };

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

proto.turnkeyAuthMW = function() {
  var self = this,
      cfg = this.config;

  return function(req, res, next) {
    var token = req.session.usertoken,
        turnkeyauth = req.headers['turnkey-auth'];

    turnkeyauth = turnkeyauth || (req && req.query && req.query.turnkeyAuth);

    if (turnkeyauth && cfg.authKeys) {
      try {
        if (req && req.query) delete req.query.turnkeyAuth;

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

  };
}

proto.turnkeyMockMW = function() {
  var self = this,
      cfg = this.config;

  return function(req, res, next) {
    var currUser = req.user,
        mockToken = req.session.mockUserToken,
        token;

    // must be turned on an cannot be only token set
    if (cfg.mockUser && mockToken && currUser) token = mockToken;
    if (cfg.mockUser && mockToken && !currUser)
      req.session.mockUserToken = null;

    if (!token) return next(), debug('No mockuser token');

    debug('mock user token: %s', token);

    cfg.deserialize(token, function(err, user) {
      if (err) return cfg.logger.error('turnkey | deserializing user: %s', err);
      debug('user is logged in: %j', user);
      if (!user) req.session.mockUserToken = null;
      req.user = user;
      req.actualUser = currUser;
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
  }
}
