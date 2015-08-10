
var tools = module.exports = exports = {},
    utile = require('utile'),
    cors = require('cors'),
    debug = require('debug')('turnkey'),
    uuid = require('uuid');

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
    logoutRedirect: function() {
      return '/#/?logout=' + Math.random();
    },

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

    codeMaker: tools.uuid(),

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

tools.uuid = function() {
  return function() { return uuid.v1(); }
}

tools.nums = function(n) {
  n = n || 5;
  return function() {
    var chars = ['2', '3', '4', '5', '6', '7', '8', '9'],
        s = '';
    while (s.length < n) s += chars[tools.randI(0, chars.length - 1)];
    return s;
  }
}

tools.randI = function(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

