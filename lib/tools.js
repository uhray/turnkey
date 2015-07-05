
var tools = module.exports = exports = {},
    utile = require('utile'),
    cors = require('cors'),
    debug = require('debug')('turnkey');

tools.default_cfg = function() {
  var cfg = {
    // Required Options --------------------------------------------------------
    router: undefined,       /* Express JS Router */
    model: undefined,        /* Mongoose model */

    // Options with defaults ---------------------------------------------------
    hashLength: 256,
    hashIterations: 12288,
    logger: console.log.bind(console),
    usernameKey: 'username',
    minLength: 8,
    verifyRedirect: '/',
    verificationOn: true,
    forgotLimit: 1000 * 60 * 60,  // 1 hour
    loginOnVerify: false,
    logoutRedirect: '/?logout=' + Math.random() + '/#/',

    deserialize: function(id, cb) {
      cfg.model.findById(id).lean().exec(cb);
    },

    serialize: function(u, cb) {
      return cb(null, String(u._id));
    },

    findUser: function(body, cb) {
      var key = cfg.username_key || cfg.usernameKey,
          uname = body && body[key] && body[key].toLowerCase(),
          q = {};

      debug('find user: %s', uname);

      q[key] = uname;
      cfg.model.findOne(q).lean().exec(cb);
    },

    // Optionals ---------------------------------------------------------------
    forgotMailer: undefined     /* Mailer when forgot password */
  };

  return cfg;
}

tools.createCors = function(obj) {
  if (!obj) return function(a, b, c) { c() };
  obj = utile.mixin({
           credentials: true,
           origin: function(o, cb) { cb(null, true); }
        }, typeof obj == 'object' ? obj : {});
  return cors(obj);
}
