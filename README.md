# turnkey

A turnkey authentication module for nodejs + expressjs + mongoosejs.

* [Quickstart](#quickstart)
* [Overview](#overview)
* [Configure](#configure)
* [Middleware](#middleware)
* [Events](#events)
* [Verification](#verification)
* [Mocking Users](#mocking-users)
* [Debug](#debug)

## Quickstart

Install:
```
npm install turnkey
```

Use:
```js
var turnkey = require('turnkey'),
    mongoose = require('mongoose'),
    app = require('express')(),
    userModel = mongoose.model('users', new mongoose.Schema({
      username: {
        type: String,
        required: true,
        index: true
      }
    });

turnkey.launch({
  router: app,
  model: userModel
});
```

This will modify the module to store turnkey information and set up routes for login/logout.

## Overview

When launched, turnkey sets up two main things: express middleware & routes.

### Express Middleware

The express middleware is pretty simple. It handles whether a user is logged in. If a user is logged in, it modifies the Express `request` object to contain the user's information on `request.user`. If there user is not logged in, nothing happens.

So, if you wanted to check if a user were logged in, you could do this:

```js
app.get('/route', function isLoggedIn(req, res, next) {
  if (req.user) return next();
  else res.send('unauthorized');
}, function handleRoute() {
  // do something here
})
```

You can look at the prebuilt middleware below for [loggedIn](#mw-loggedIn) for a prebuilt function with that functionality and more, but this explains nicely what's going on.

### Routes

Turnkey sets the following routes on the Express Router by default.

* `POST` on `/turnkey/login` - This listens for a POST request. The request body is passed to the `findUser` configuration function (see below). If a user is found, it is authenticated against the password located at `body.password`. The response object is JSON and contains and*error* value if there was an error and a *data* value if the user was successfully authenticated. The *data* value will be the user's unique Mongo ID.

* `GET` on `/turnkey/logout` - This removes the authentication cookie and redirects to the homepage.

Additionally, if you set the `forgotMailer` configuration (see below), then the following routes will be set:

* `POST` on `/turnkey/forgot` - This listens for a POST request. The request body is passed to the `findUser` configuration function (see below). If a user is found, the user is modified to store a token used for password reset. The response object is JSON and contains an *error* value if there was an error and a truthy *data* value if the user was successfully found and a token was set.
 
* `PUT` on `/turnkey/reset` - This listens for a PUT request to modify the user with the new password. The request body must have two values: *code*, containing the code created in the `/turnkey/forgot` route and handled by the `forgotMailer` function, and *password*, containing the new password. The response object is JSON and contains an *error* value if there was an error and a truthy *data* value if the password was successfully reset.

* `GET` on `/turnkey/verify/:code` - This listens for a GET request to update the users as verified. After verification (success or failure), it redirects to the configuration `verifyRedirect` url with url params. See Examples:

  - Success: http://site.com/?turnkey-verification=success
  - Failure: http://site.com/?turnkey-verification=failure

  > If you want a JSON response instead of a redirect, add `?json=true` to the request.

* `GET` on `/turnkey/mockUser/:user` - This listens for a GET request to set the current user's authentication to a new user. For more information, see [mocking users](#mocking-users) or [configurations](#configure).

## Configure

To add turnkey to your application, you must launch it with configurations. Some required, some option.

Launch like this:

```js
var turnkey = require('turnkey');

turnkey.launch({ /* configurations */ });
```

Available Configurations:

  * `router` - *Required* - Express JS Router. This router will be used to listen for routes on the server.

  * `model` - *Required* - Mongoose JS User Model. This object will be modified with a "turnkey" object that contains useful information for turnkey.

  * `hashLength` - *Default = 256* - length for [pwd](https://www.npmjs.org/package/pwd) hash.

  * `hashIterations` - *Default = 12288* - iterations for [pwd](https://www.npmjs.org/package/pwd) salt.

  * `logger` - *Default = console.log* - used to log errors.

  * `usernameKey` - *Default = "username"* - the key on the `model` that stores the unique username. This is used for the default `findUser` function. If you override that function, this is not used by Turnkey.

  > Previously, this was titled "username_key". If you are still using that, it is backwards compatible, but we prefer camelCase.

  * `minLength` - *Default = 8* - default minimum password length.

  * `verificationOn` - *Default = true* - Requires users to be verified before the default `findUser` works.

  * `verifyRedirect` - *Default = "/"* - URL to redirect user once they hit the verification link.

  * `loginOnVerify` - *Default = false* - Logs the user in when they verify their email.

  * `logoutRedirect` - *Default = function* - Function that decides thes logout redirect url. By default the function returns `'/#/?logout=Math.random()'`.

  * `forgotLimit` - *Default = 1000 * 60 * 60 (1 hour)* - Limit for how long the forgot password code is active for. After this time limit, the user would need to do forgot password again before resetting. This is only used if the `forgotMailer` is set.

  * `deserialize` - *Default = uses Mongoose findById on the model* - This function is passed (*id*, *callback*) and expects the *callback* to be called with (*error*, *user*). Basically, it's supposed to convert an *id* to a *user*. 

  * `serialize` - *Default = returns user._id* - This function is passed (*user*, *callback*) and is expected to call the *callback* with (*error*, *id*). Basically, it's supposed to convert a *user* to an *id*.

  * `findUser` - *Default = finds user by username using the usernameKey configuration* - This function is called with (*body*, *callback*), where the *body* is the POST requests body and the *callback* is supposed to be called with (*error*, *user*). This is called when there is a POST request on the `/turnkey/login` route. By default, it expects the POST data to have `{ username: '<my username>' }`, because the `usernameKey` is `"username"` by default.

  * `forgotMailer` - Optional - This is an optional function that can email a user when the forgot password route is hit. If this is null, the forgot & reset password routes will not be set. This will provide you (*user*, *code*, *callback*), where the user is the deserialized user object, the *code* is the code provided from the forgot password post and ready for the reset password, and the callback is to be called when done with (*error*). Additionally, the express request and response will be in the context as `this.request` and `this.response`.

  * `cors` - Optional - This is an optional configuration to allow [cors](https://www.npmjs.org/package/cors) requests. If truthy and not an object, it creates a configuration for [cors](https://www.npmjs.org/package/cors) that allows all origins to request cross-origin and allows credentials to be stored. If the configuration is an object, this object will be passed as the options to the [cors](https://www.npmjs.org/package/cors) middleware.

  * `codeMaker` - Default = `turnkey.tools.uuid()` - This is an optional configuration that allows you to change the codemaker for verification. By default it's a uuid, but you can set it to other things;.

    * `turnkey.tools.uuid()` - Returns a function that creates a uuid;

    * `turnkey.tools.nums(n)` - Returns a function that creates a random strong of numbers `n` characters long.

  * `authKeys` - Optional - These are keys passed to [keygrip](https://www.npmjs.com/package/keygrip) with allow you to authenticate via the header `Turnkey-Auth`. You provide the data returned from `/turnkey/login` as the header to be logged in here.

  * `verifyPassword` - Optional - This is an option function that can verify the acceptance of a password. It's called with one argument (the password) and much return a truthy validity. An example would be to require all passwords have a symbol and number.

  * `mockUser` - *Default: false* - This allows users to mock control of another user. Turned off by default.

  * `mockUserAuth` - *Default: everyone* - If *mockUser* is turned on, this is a function that is passed the current user object and must return a true or false value as to whether the current user should be able to mock another. A good example is restricting mock access to those that are admins.

  * `mockUserKey` - *Default: 'username'* - To mock a user, they must go to the link `/turnkey/mockUser/:user`, where the user param will be searched against the mockUserKey. Default is looking for the username. Another common one would be email.

  * `mockUserRedirect` - *Default: '/'* - After the `/turnkey/mockUser/:user` url is hit, it will redirect to this url and act as the new user.

## Middleware

The following are special Express Middleware functions provided by the turnkey module. This Middleware functions are especially useful with [crud](https://github.com/uhray/crud) and [crud-mongoose](https://github.com/uhray/crud-mongoose).

<a href="mw-createPassword" name="mw-createPassword">#</a> turnkey.**createPassword**()

This creates a middleware function to modify the requests `data` object to contain the necessary information to create a password for a user. If this middleware is set, it ensure the request body has a valid value at `body.password`, which would be the password, and modifies the object to remove that password and then contain the necessary information that should be inserted into the Mongoose model for use with turnkeys' authentication.

It's a bit confusing to explain, but super simple to use. If you're using crud and crud-mongoose, you could use it like this:

```js
crud.entity('/users').Create()
  .use(turnkey.createPassword())
  .pipe(cm.createNew(Model));
```

This ensures that if you're creating a new user, the correct information is set so this user has authentication capability.

<a href="mw-updatePassword" name="mw-updatePassword">#</a> turnkey.**updatePassword**(*cb*)

This creates a middleware function to modify the requests `data` object to contain the necessary information to update a password for a user. This middleware ignores everything if there is no `body.password` information. BUT, if there is a value at `body.password`, this ensures there is also a value at `body.oldPassword` and that the old password correctly authenticates the logged in user. It is standard for password updates to require authentication right there, so this is built in. If this old password is correct, then it modifies the object to remove `body.password` and `body.oldPassword` and then contain the necessary information that should be inserted into the Mongoose model for use with turnkeys' authentication. (note: `old_password` still works but is relegated).

ALERNATIVELY, you can pass a callback function as *cb* that will determine if `oldPassword` is required. This is useful for an admin panel where certain users (e.g. admins) can update anyone's password. The callback function is called `cb(req, res)` and must return a truthy value as to whether the user can update without `oldPassword` present.

Again, it's a bit confusing to explain, but super simple to use. If you're using crud and crud-mongoose, you could use it like this:

```js
crud.entity('/users/:_id').Update()
  .use(turnkey.updatePassword())
  .pipe(cm.updateOne(Model));
```

This ensures that if you're updating a user and want to update the password then: 
  * The correct information is set so this user has authentication capability
  * The `body.oldPassword` field accurate authenticates the logged in user

<a href="#mw-loggedIn" name="mw-loggedIn">#</a> turnkey.**loggedIn**([*vals*])

This route is used to prevent a user from accessing routes he/she is unauthorized to access.

If *vals* is not set, then it just makes sure any user is logged in (similar to the example [here](#express-middleware)). Use like this:

```js
crud.entity('/users').Read()
  .use(turnkey.loggedIn())
  .pipe(cm.findAll(Model));
```

However, *vals* allows you to be more specific with who must be logged in. It's a key-value pairing that makes sure the logged in user has those key-values set. So, the following makes sure the user is an admin:

```js
crud.entity('/users').Read()
  .use(turnkey.loggedIn({ role: 'admin' }))
  .pipe(cm.findAll(Model));
```

Or, if the value in the key-value pairing is an array, this ensures that the key is one of the provided options. So, the following makes sure the user is an admin or root.

```js
crud.entity('/users').Read()
  .use(turnkey.loggedIn({ role: ['admin', 'root'] }))
  .pipe(cm.findAll(Model));
```

<a href="#mw-checkResend" name="mw-checkResend">#</a> turnkey.**checkResend**([*cb*, *modify*])

This is useful middleware to check if you need to resend a verification email to someone who tries to signup again. Usually, a database would fail if the user already exists. This allows you to resend and email and act like they just signed up, so it's not confusing to a new user.

If the user does not exists OR the user exists but is already verified, nothing happens. If the user exists AND has not verified, this will respond from the server with that user's information to make it appear like the user was just recreated.

  * *cb* - A callback that receives the user object if an unverified user was trying to re-signup. The use for this is to probably resend a verification email.
  * *modify* - This allows you to modify the user object before it is responded from the server. Perhaps you'd want to remove personal information if the user already exists.

## Events

Events can be accessed by running the following:

```js
var turnkey = require('turnkey');

turnkey.on('eventName', function(args) {
  // function called when event fires
});
```

The available events are below:

  * *verification* - Call when a user is verified. Arguments: (*userObject*).


## Verification

Verification gets its own section because it does things a bit uniquely. Turnkey modifies the user model to store the necessary authentication information. It also stores verfiication information:

```js
user.verification: {
  code: { type: String, default: uuidCreator },
  verified: {
    type: Boolean,
    default: cfg.verificationOn ? false : true
  }
}
```

So, after a user is created in the database, you may want to send them and email with user.verification.code as the code in the URL.

> It is very important to realize that you never want to show anyone the code when it hasn't been emailed to them. So you should never respond to the person who created the user with the code information. It should only be sent via email.

## Mocking Users

To mock users, you need to see the necessary [configurations](#configure). But, after mocking users is turned on a configured, you can do the following:

Say you are user `admin` and want to be user `user1`. You can go to the user `/turnkey/mockUser/user1`. Now, everything you do on the site will make you act like `user1`. To switch back, you must logout and you will be logged out as `user1` and back to being `admin`.

## Debug

The Turnkey module has sprinkled some [debug](https://github.com/visionmedia/debug) messages throughout the module. If you wish to turn these on, run your sever with the environment variable `DEBUG=turnkey` set.
