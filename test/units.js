var test = require('unit.js'),
    turnkey = require('../index'),
    mongoose = require('mongoose'),
    async = require('async'),
    tools = require('../lib/tools');

describe('tools', function() {

  it('tools.defaultCfg', function() {
    var o = tools.defaultCfg();

    o.must.be.a.object();
    Object.keys(o).length.must.be.gt(10);
  });

  it('tools.createCors', function() {
    var hasCors;

    test.when('No cors', function() {})
      .then(function() {
        var x = tools.createCors(hasCors),
            nextCalled = false,
            next = function() {
              nextCalled = true;
            };

        x(null, null, next);
        nextCalled.must.be.true();
      })
      .when('Yes cors', function() {
        hasCors = true;
      })
      .then(function() {
        var x = tools.createCors(hasCors),
            nextCalled = false,
            next = function() {
              nextCalled = true;
            };

        x.bind({}, null, null, next)
         .must.throw();
        nextCalled.must.be.false();
      })
  });

  it('tools.uuid', function() {
    var uuid = tools.uuid(),
        i = 0, id;

    uuid.must.be.a.function();

    while (i++ < 100) {
      id = uuid();
      id.must.be.a.string();
      id.must.match(
        /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/
      );
    }
  });

  it('tools.nums', function() {
    var nums = tools.nums(),
        i = 0, id;

    nums.must.be.a.function();

    while (i++ < 100) {
      id = nums();
      id.must.be.a.string();
      id.must.match(/[2-9]{5}/);
    }

    nums = tools.nums(7);

    nums.must.be.a.function();

    while (i++ < 100) {
      id = nums();
      id.must.be.a.string();
      id.must.match(/[2-9]{7}/);
    }
  });

  it('tools.randI', function() {
    var is = [],
        min = 13,
        max = 27;

    test.when('test a bunch', function() {
          var i = 0;

          while (i++ < 1000) is.push(tools.randI(min, max))
        })
        .then(function() {
          is.forEach(function(d) {

            d.must.be.lte(max);
            d.must.be.gte(min);
            test.assert.deepEqual(d % 1, 0, 'Must be integer');
          });
        });
  });

});

describe('proto', function() {

  it('proto.launch', function() {
    var getRoute = [],
        postRoute = [],
        useCalled = [],
        addCalled = [],
        optionsCalled = [],
        putRoute = [],
        mock = {
          mongoose: mongoose,
          forgotMailer: true,
          model: mongoose.model('users', new mongoose.Schema({
            test: 'string'
          })),
          model: {
            schema: {
              add: function(d) {
                addCalled.push(d);
              }
            }
          },
          router: {
            get: function(r) {
              getRoute.push(r);
            },
            post: function(r) {
              postRoute.push(r);
            },
            put: function(r) {
              putRoute.push(r);
            },
            use: function(d) {
              useCalled.push(d);
            },
            options: function(d) {
              optionsCalled.push(d);
            }
          }
        };

    // must provide useful stuff for these three
    turnkey.launch.bind(turnkey).must.throw();
    turnkey.launch.bind(turnkey, { router: true }).must.throw();
    turnkey.launch.bind(turnkey, {
      router: true,
      deserialize: true
    }).must.throw();
    turnkey.launch.bind(turnkey, {
      router: true,
      deserialize: true,
      serialize: true
    }).must.throw();
    turnkey.launch.bind(turnkey, {
      router: true,
      deserialize: true,
      serialize: true,
      findUser: true
    }).must.throw();
    turnkey.launch.bind(turnkey, {
      router: true,
      deserialize: true,
      serialize: true,
      model: true
    }).must.throw();

    turnkey.launch(mock);

    useCalled.length.must.equal(1);
    addCalled.length.must.equal(1);
    addCalled[0].must.be.a.object();
    optionsCalled.length.must.equal(0);

    getRoute.must.contain('/turnkey/logout');
    getRoute.must.contain('/turnkey/verify/:code');
    getRoute.length.must.equal(2);

    postRoute.must.contain('/turnkey/login');
    postRoute.must.contain('/turnkey/forgot');
    postRoute.length.must.equal(2);

    putRoute.must.contain('/turnkey/reset');
    putRoute.length.must.equal(1);

    mock.cors = true;
    turnkey.launch(mock);
    optionsCalled.length.must.equal(5);
    optionsCalled.must.contain('/turnkey/logout');
    optionsCalled.must.contain('/turnkey/verify/:code');
    optionsCalled.must.contain('/turnkey/login');
    optionsCalled.must.contain('/turnkey/forgot');
    optionsCalled.must.contain('/turnkey/reset');

  });

  it('proto.makeHash', function(done) {
    turnkey.makeHash('testpassword', function(e, salt, hash) {
      test.assert(e == null);
      salt.must.be.a.string();
      hash.must.be.a.string();
      done();
    });
  });

  it('proto.verify', function(done) {
    turnkey.makeHash('testpassword', function(e, salt, hash) {
      turnkey.verify('testpassword', { salt: salt, hash: hash }, function(v) {
        test.assert(v);
        done();
      });
    });
  });

  it('proto.errorObject', function() {
    var e = turnkey.errorObject(1, 'test');

    e.must.eql({
      error: {
        msg: 'test',
        code: 1,
        source: 'turnkey'
      }
    });
  });

  it('proto.createPassword', function(done) {
    var fn = turnkey.createPassword(),
        jsonRes = null,
        res = { json: function(r) {
          jsonRes = r;
          jsonFn(r);
        } },
        next = function() {
        },
        jsonFn = function() {},
        body;

    // must fail if not passed right stuff
    fn.bind(fn).must.throw();

    // no password provided
    fn({ body: {} }, res);
    test.assert(jsonRes);
    jsonRes.error.code.must.equal(1);
    jsonRes = null;

    // test short
    fn({ body: { password: 'short' } }, res);
    test.assert(jsonRes);
    jsonRes.error.code.must.equal(1);
    jsonRes = null;

    // test success
    body = { turnkey: true }
    body['turnkey.verification'] = true;
    body['turnkey.verification.verified'] = true;
    body.password = 'testpassword';
    jsonFn = function(d) {
      assert(false, 'Should not get here');
    };
    fn({ body: body }, res, function() {
      test.assert(body && body.turnkey && body.turnkey.password);
      test.assert(!body['turnkey.verification']);
      test.assert(!body['turnkey.verification.verified']);

      turnkey.verify(
        'testpassword',
        body.turnkey.password,
        function(v) {
          test.assert(v, 'password verification failed');
          done();
        }
      );
    });
    test.assert(!jsonRes);
  });

  it('proto.updatePassword', function(done) {
    var body = {},
        doJson = function() {},
        res = {
          json: function(x) {
            doJson(x);
          }
        },
        req = { body: body };

    async.series([
      function(cb) {
        var fn = turnkey.updatePassword(),
            nexted;

        fn(req, null, function() {
          nexted = true;
        });
        test.assert(nexted, 'should have called next');
        cb();
      },
      function(cb) {
        var fn = turnkey.updatePassword(),
            code, msg;
            //res = { json: doJson };

        doJson = function(e) {
          test.assert(e.error.code == code, 'failed code: ' + msg);
        };

        msg = 'short password';
        body.password = 't';
        code = 1;
        fn(req, res, next);

        msg = 'not logged in';
        body.password = 'tthisislongenough';
        code = 6;
        fn(req, res, next);

        msg = 'not logged in';
        body.oldPassword = 'old';
        code = 6;
        fn(req, res, next);

        msg = 'not correct old password';
        body.oldPassword = 'old';
        req.user = { turnkey: { password: { salt: 'salt', hash: 'hash' } } };
        doJson = function(e) {
          e.error.code.must.equal(6);
          cb();
        };
        fn(req, res, next);

        function next() {
          test.assert(false, 'Should not get here: ' + msg);
        }
      },
      function(cb) {  // works with old password
        var fn = turnkey.updatePassword();

        turnkey.makeHash('testpassword', function(e, salt, hash) {
          body.oldPassword = 'testpassword';
          req.user = { turnkey: { password: { salt: salt, hash: hash } } };

          doJson = function(e) {
            test.assert(false, 'Should not get here: ' + JSON.stringify(e));
          };

          fn(req, res, function() {
            test.assert(!body.password);
            test.assert(!body.oldPassword);
            body.turnkey.password.must.be.a.object();
            body.turnkey = null;  // reset
            cb();
          });
        });
      },
      function(cb) {  // works without old password
        var fn = turnkey.updatePassword(function() { return true; });

        body.oldPassword = null;
        req.user = null;
        body.password = 'mypassword';

        doJson = function(e) {
          test.assert(false, 'Should not get here: ' + JSON.stringify(e));
        };

        fn(req, res, function() {
          test.assert(!body.password);
          test.assert(!body.oldPassword);
          body.turnkey.password.must.be.a.object();
          cb();
        });
      }
    ], function(e) {
      test.assert(!e, 'error occured');
      done();
    });

  });

  it('proto.loggedIn', function() {
    var req = { user: {} },
        calledJson = false,
        calledNext = false,
        doJson = function() { calledJson = true; },
        next = function() { calledNext = true; },
        res = { json: function(e) { doJson(e); } },
        fn;

    // not logged in
    fn = turnkey.loggedIn();
    calledJson = false;
    calledNext = false;
    req.user = {};
    fn(req, res, next);
    calledJson.must.be.true();
    calledNext.must.be.false();

    // logged in
    fn = turnkey.loggedIn();
    calledJson = false;
    calledNext = false;
    req.user = { _id: 'myid' };
    fn(req, res, next);
    calledJson.must.be.false();
    calledNext.must.be.true();

    // key value - true
    fn = turnkey.loggedIn({ key: 'value' });
    calledJson = false;
    calledNext = false;
    req.user = { _id: 'myid', key: 'value' };
    fn(req, res, next);
    calledJson.must.be.false();
    calledNext.must.be.true();

    // key value - false
    fn = turnkey.loggedIn({ key: 'value' });
    calledJson = false;
    calledNext = false;
    req.user = { _id: 'myid', key: 'notvalue' };
    fn(req, res, next);
    calledJson.must.be.true();
    calledNext.must.be.false();

    // array - false
    fn = turnkey.loggedIn({ key: 'value' });
    calledJson = false;
    calledNext = false;
    req.user = { _id: 'myid', key: ['value'] };
    fn(req, res, next);
    calledJson.must.be.false();
    calledNext.must.be.true();

    // array - false
    fn = turnkey.loggedIn({ key: 'value' });
    calledJson = false;
    calledNext = false;
    req.user = { _id: 'myid', key: ['notvalue'] };
    fn(req, res, next);
    calledJson.must.be.true();
    calledNext.must.be.false();
  });

  it('proto.checkResend', function(done) {

    async.series([
      function(cb) {
        turnkey.config.findUser = function(n, cb) {
          cb();
        };

        turnkey.checkResend()({}, {}, function() {
          cb();  // must just get here
        });
      },

      function(cb) {
        var didCB = false,
            didModify = false;

        turnkey.config.findUser = function(n, cb) {
          cb(null, {
            turnkey: { verification: { verified: false } }
          });
        };

        turnkey.checkResend(callback, modify)({}, { json: function(d) {
          didCB.must.be.true();
          didModify.must.be.true();
          d.data.must.equal('test');
          cb();
        } }, function() {
          test.assert(false, 'must not get here');
        });

        function callback() {
          didCB = true;
        }

        function modify(d) {
          didModify = true;
          test.assert(!d.turnkey, 'must have deleted this');
          return 'test';
        }
      }

    ], function(e) {
      test.assert(!e, 'error occured');
      done();
    });
  });

});
