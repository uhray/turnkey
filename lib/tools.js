
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

    deserialize: function(id, cb) {
      cfg.model.findOne({ _id: id }, function(e, d) {
        d = (d && d.toJSON) ? d.toJSON({ getters: true }) : d;
        cb(e, d);
      });
    },

    serialize: function(u, cb) {
      return cb(null, String(u._id));
    },

    find_user: function(body, cb) {
      var uname = body && body[cfg.username_key] &&
                  body[cfg.username_key].toLowerCase(),
          q = {};

      q[cfg.username_key] = uname;
      cfg.model.findOne(q, function(e, d) {
        d = (d && d.toJSON) ? d.toJSON({ getters: true }) : d;
        cb(e, d);
      });
    },

    // Optionals ---------------------------------------------------------------
    mailer: undefined     /* Mailer */
  };

  return cfg;
}

