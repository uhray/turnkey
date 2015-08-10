
var utile = require('utile'),
    proto = require('./proto'),
    tools = require('./tools');

module.exports = exports = new TurnKey();

function TurnKey(options) {
  if (!(this instanceof TurnKey)) return new TurnKey(options);
  this.config = utile.mixin(tools.default_cfg(), options || {});
}

TurnKey.prototype._create = TurnKey;
TurnKey.prototype = utile.mixin(TurnKey.prototype, proto);
TurnKey.prototype.tools = tools;
