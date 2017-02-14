
var tools = module.exports = exports = {},
    utile = require('utile'),
    cors = require('cors'),
    debug = require('debug')('turnkey'),
    FB = require('fb'),
    request = require('request'),
    Twitter = require('twitter'),
    _ = require('lodash'),
    uuid = require('uuid');

tools.defaultCfg = function() {
  var cfg = {
    // Required Options --------------------------------------------------------
    router: undefined,       /* Express JS Router */
    model: undefined,        /* Mongoose model */

    // Options with defaults ---------------------------------------------------
    hashIterations: 10,
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
      cfg.model.findOne({ 'turnkey.uuid': id }).lean().exec(cb);
    },

    serialize: function(u, cb) {
      return cb(null, String(_.get(u, 'turnkey.uuid')));
    },

    findUser: function(body, cb) {
      // jscs:disable
      var key = cfg.username_key || cfg.usernameKey,
      // jscs:enable
          uname = body && body[key] && body[key].toLowerCase(),
          q = {};

      debug('find user: %s', uname);

      q[key] = uname;
      cfg.model.findOne(q).lean().exec(cb);
    },

    codeMaker: tools.uuid(),

    mockUserAuth: function() { return true; },
    mockUserRedirect: '/',
    mockUserKey: 'username',
    socialSecrets: {},

    // Optionals ---------------------------------------------------------------
    forgotMailer: undefined,     /* Mailer when forgot password */
    authKeys: undefined,         /* Allow auth via turnkey-auth header */
    mockUser: false,             /* Allow user mocking */
    socialAuth: false,           /* Allow social login */
    socialCreate: undefined,     /* Function for creating social user */
    socialUpdate: undefined      /* Function for updating social user */
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
  return function() { return uuid.v4(); }
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

tools.verifyNetwork = function(userid, network, token, client, secret, cb) {
  if (network == 'facebook') facebook();
  else if (network == 'twitter') twitter();
  else if (network == 'google') google();
  else if (network == 'linkedin') linkedin();
  else cb(false);

  function facebook() {
    FB.options({ appSecret: secret, appId: client });

    // jscs:disable
    FB.api(
      'me',
      { fields: ['id'], access_token: token, appSecret: secret },
      function(res) {
        if (!(res && res.id)) cb(false);
        else cb((res && res.id) == userid);
      }
    );
    // jscs:enable
  }

  function twitter() {
    // jscs:disable
    var keys = token.replace(/@.*/, '').split(':'),
        tclient = new Twitter({
          consumer_key: client,
          consumer_secret: secret,
          access_token_key: keys[0],
          access_token_secret: keys[1]
        });

    tclient.get('account/verify_credentials', function(e, d) {
      if (!(d && d .id)) cb(false);
      else cb((d && d.id) == userid);
    });
    // jscs:enable
  }

  function google() {
    // jscs:disable
    var url = 'https://www.googleapis.com/plus/v1/people/me';

    request({
      url: url,
      qs: { access_token: token },
      json: true
    }, function(e, res, d) {
      if (!(d && d .id)) cb(false);
      else cb((d && d.id) == userid);
    });
    // jscs:enable
  }

  function linkedin() {
    // jscs:disable
    var url = 'https://api.linkedin.com/v1/people/' +
              '~:(picture-url,first-name,last-name,id,' +
                  'formatted-name,email-address)';

    request({
      url: url,
      qs: {
        format: 'json',
        oauth2_access_token: token
      },
      json: true
    }, function(e, res, d) {
      if (!(d && d .id)) cb(false);
      else cb((d && d.id) == userid);
    });
    // jscs:enable
  }
}
