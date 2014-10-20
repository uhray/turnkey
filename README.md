# turnkey

A turnkey authentication module for nodejs + expressjs + mongoosejs.

* [Quickstart](#quickstart)
* [Overview](#overview)
* [Configure](#configure)
* [Middleware](#middleware)
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

You can look at the prebuilt middleware below for [loggedIn](mw-loggedIn) for a prebuilt function with that functionality and more, but this explains nicely what's going on.

### Routes

Turnkey sets the following routes on the Express Router by default.

* `POST` on `/turnkey/login` - This listens for a POST request. The request body is passed to the `find_user` configuration function (see below). If a user is found, it is authenticated against the password located at `body.password`. The response object is JSON and contains and*error* value if there was an error and a *data* value if the user was successfully authenticated. The *data* value will be the user's unique Mongo ID.

* `GET` on `/turnkey/logout` - This removes the authentication cookie and redirects to the homepage.

Additionally, if you set the `forgot_mailer` configuration (see below), then the following routes will be set:

* `POST` on `/turnkey/forgot` - This listens for a POST request. The request body is passed to the `find_user` configuration function (see below). If a user is found, the user is modified to store a token used for password reset. The response object is JSON and contains an *error* value if there was an error and a truthy *data* value if the user was successfully found and a token was set.
 
* `PUT` on `/turnkey/reset` - This listens for a PUT request to modify the user with the new password. The request body must have two values: *code*, containing the code created in the `/turnkey/forgot` route and handled by the `forgot_mailer` function, and *password*, containing the new password. The response object is JSON and contains an *error* value if there was an error and a truthy *data* value if the password was successfully reset.

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

  * `hash_length` - *Default = 256* - length for [pwd](https://www.npmjs.org/package/pwd) hash.

  * `hash_iterations` - *Default = 12288* - iterations for [pwd](https://www.npmjs.org/package/pwd) salt.

  * `logger` - *Default = console.log* - used to log errors.

  * `username_key` - *Default = "username"* - the key on the `model` that stores the unique username. This is used for the default `find_user` function. If you override that function, this is not used by Turnkey.

  * `min_length` - *Default = 8* - default minimum password length.

  * `forgot_limit` - *Default = 1000 * 60 * 60 (1 hour)* - Limit for how long the forgot password code is active for. After this time limit, the user would need to do forgot password again before resetting. This is only used if the `forgot_mailer` is set.

  * `deserialize` - *Default = uses Mongoose findById on the model* - This function is passed (*id*, *callback*) and expects the *callback* to be called with (*error*, *user*). Basically, it's supposed to convert an *id* to a *user*. 

  * `serialize` - *Default = returns user._id* - This function is passed (*user*, *callback*) and is expected to call the *callback* with (*error*, *id*). Basically, it's supposed to convert a *user* to an *id*.

  * `find_user` - *Default = finds user by username using the username_key configuration* - This function is called with (*body*, *callback*), where the *body* is the POST requests body and the *callback* is supposed to be called with (*error*, *user*). This is called when there is a POST request on the `/turnkey/login` route. By default, it expects the POST data to have `{ username: '<my username>' }`, because the `username_key` is `"username"` by default.

  * `forgot_mailer` - Optional - This is an optional function that can email a user when the forgot password route is hit. If this is null, the forgot & reset password routes will not be set. This will provide you (*user*, *code*, *callback*), where the user is the deserialized user object, the *code* is the code provided from the forgot password post and ready for the reset password, and the callback is to be called when done with (*error*).

## Middleware

The following are special Express Middleware functions provided by the turnkey module. This Middleware functions are especially useful with [crud](https://github.com/uhray/crud) and [crud-mongoose](https://github.com/uhray/crud-mongoose).

<a href="mw-createPassword" name="mw-createPassword">#</a> turnkey.**createPassword**()

This creates a middleware function to modify the requests `data` object to contain the necessary information to create a password for a user. If this middleware is set, it ensure the request body has a valid value at `body.password`, which would be the password, and modifies the object to remove that password and then contain the necessary information that should be inserted into the Mongoose model for use with turnkeys' authentication.

It's a bit confusing to explain, but super simple to use. If you're using crud and crud-mongoose, you could use it like this:

```
crud.entity('/users').Create()
  .use(turnkey.createPassword())
  .pipe(cm.createNew(Model));
```

This ensures that if you're creating a new user, the correct information is set so this user has authentication capability.

<a href="mw-updatePassword" name="mw-updatePassword">#</a> turnkey.**updatePassword**()

This creates a middleware function to modify the requests `data` object to contain the necessary information to update a password for a user. This middleware ignores everything if there is no `body.password` information. BUT, if there is a value at `body.password`, this ensures there is also a value at `body.old_password` and that the old password correctly authenticates the logged in user. It is standard for password updates to require authentication right there, so this is built in. If this old password is correcty, then modifies the object to remove `body.password` and `body.old_password` and then contain the necessary information that should be inserted into the Mongoose model for use with turnkeys' authentication.

Again, it's a bit confusing to explain, but super simple to use. If you're using crud and crud-mongoose, you could use it like this:

```
crud.entity('/users/:_id').Update()
  .use(turnkey.updatePassword())
  .pipe(cm.updateOne(Model));
```

This ensures that if you're updating a user and want to update the password then: 
  * The correct information is set so this user has authentication capability
  * The `body.old_password` field accurate authenticates the logged in user

<a href="mw-loggedIn" name="mw-loggedIn">#</a> turnkey.**loggedIn**([*vals*])

This route is used to prevent a user from accessing routes he/she is unauthorized to access.

If *vals* is not set, then it just makes sure any user is logged in (similar to the example [here](#express-middleware)). Use like this:

```
crud.entity('/users').Read()
  .use(turnkey.loggedIn())
  .pipe(cm.findAll(Model));
```

However, *vals* allows you to be more specific with who must be logged in. It's a key-value pairing that makes sure the logged in user has those key-values set. So, the following makes sure the user is an admin:

```
crud.entity('/users').Read()
  .use(turnkey.loggedIn({ role: 'admin' }))
  .pipe(cm.findAll(Model));
```

Or, if the value in the key-value pairing is an array, this ensures that the key is one of the provided options. So, the following makes sure the user is an admin or root.

```
crud.entity('/users').Read()
  .use(turnkey.loggedIn({ role: ['admin', 'root'] }))
  .pipe(cm.findAll(Model));
```

## Debug

The Turnkey module has sprinkled some [debug](https://github.com/visionmedia/debug) messages throughout the module. If you wish to turn these on, run your sever with the environment variable `DEBUG=turnkey` set.
