# turnkey

A turnkey authentication module for nodejs + expressjs + mongoosejs.

* [Quickstart](#quickstart)
* [Guide](#guide)
* [API](#api)
* [Future Work](#future-work)

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
  user = mongoose.model('users', new mongoose.Schema({
    username: {
      type: String,
      required: true,
      index: true
    }
  });

turnkey.launch({
  router: app,
  model: 
});
```

## Guide



## API

There are two main parts to the API:

  * [configurations](#configurations)
  * [prototype](#prototype)

### Configurations

### Prototype

## Future Work

 * Reset Password
 * Change Email ... is this related?
