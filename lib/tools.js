
var tools = module.exports = exports = {},
    debug = require('debug')('turnkey');

tools.default_cfg = function() {
  var cfg = {
    // Required Options --------------------------------------------------------
    router: undefined,       /* Express JS Router */
    model: undefined,        /* Mongoose model */

    // Options with defaults ---------------------------------------------------
    hash_length: 256,
    hash_iterations: 12288,
    logger: console.log.bind(console),
    username_key: 'username',
    min_length: 8,
    forgot_limit: 1000 * 60 * 60,  // 1 hour

    deserialize: function(id, cb) {
      cfg.model.findById(id).lean().exec(cb);
    },

    serialize: function(u, cb) {
      return cb(null, String(u._id));
    },

    find_user: function(body, cb) {
      var uname = body && body[cfg.username_key] &&
                  body[cfg.username_key].toLowerCase(),
          q = {};

      debug('find user: %s', uname);

      q[cfg.username_key] = uname;
      cfg.model.findOne(q, function(e, d) {
        d = (d && d.toJSON) ? d.toJSON({ getters: true }) : d;
        cb(e, d);
      });
    },

    // Optionals ---------------------------------------------------------------
    forgot_mailer: undefined     /* Mailer when forgot password */
  };

  return cfg;
}

