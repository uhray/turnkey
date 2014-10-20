
var tools = module.exports = exports = {},
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
    username_key: 'username',
    minLength: 8,
    forgotLimit: 1000 * 60 * 60,  // 1 hour

    deserialize: function(id, cb) {
      cfg.model.findById(id).lean().exec(cb);
    },

    serialize: function(u, cb) {
      return cb(null, String(u._id));
    },

    findUser: function(body, cb) {
      var uname = body && body[cfg.username_key] &&
                  body[cfg.username_key].toLowerCase(),
          q = {};

      debug('find user: %s', uname);

      q[cfg.username_key] = uname;
      cfg.model.findOne(q).lean().exec(cb);
    },

    // Optionals ---------------------------------------------------------------
    forgotMailer: undefined     /* Mailer when forgot password */
  };

  return cfg;
}

