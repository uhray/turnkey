// Tools for encrypting and decrypting passwords.
// Basically promise-friendly wrappers for bcrypt.
var bcrypt = require('bcryptjs'),
    pwd = exports = module.exports = {
      saltIterations: 10
    };

try {
  bcrypt = require('bcrypt');
} catch (e) {}

pwd.iterations = function(d) {
  return pwd.saltIterations = d;
};

pwd.hash = function(a, b, fn) {
  if (!fn) {
    fn = b;
    b = pwd.saltIterations;
  }
  bcrypt.hash(a, b, fn);
};

pwd.compare = function(pwd, hashed, fn) {
  bcrypt.compare(pwd, hashed, fn);
};
