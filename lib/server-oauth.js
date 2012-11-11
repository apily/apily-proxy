/** oauth server **/

var fs = require('fs');
var oauth = require('oauth');
var OAuth = oauth.OAuth;
var request = require('superagent');
var sa = request.agent();
var express = require('express');
var server = express();

exports.start = function(options) {
  var options = options || {};
  var port = options.port || 8002;
  var front_port = options.front_port || 8000;
  var apily_server = options.apily_server || 'http://romejs.nko3.jitsu.com';

  var api_keys = {};

  fs.readFile('apily.json', 'utf-8', function(err, data) {
    if (err) {
      throw 'Error check your apily.json file.';
    }

    var parsed_data = JSON.parse(data);
    var application_name = parsed_data.name;
    parsed_data.services.forEach(function(service) {
      api_keys[service.name] = {};
      api_keys[service.name].consumer_secret = service.consumer_secret;
      api_keys[service.name].consumer_key = service.consumer_key;
    });

    sa
      .post(apily_server + '/apily/0/app/create')
      .send({
        name: application_name
      })
      .end(function(err, sa_res) {
        if (err) {
          res.status(sa_res.statusCode).send('db comunication error');
          return;
        }

        server.configure(function() {
          server.use(express.favicon());
          server.use(express.logger('dev'));
          server.use(express.cookieParser());
          server.use(express.cookieSession({secret: 'nodeko2013 keyphrase'}));
          server.use(express.bodyParser());
          server.use(express.methodOverride());
        });

        server.configure('development', function() {
          server.use(express.errorHandler());
        });

        server.configure('production', function() {
          front_port = 80;
        });

        server.listen(port, function() {
          console.log('Oauth server listening on port ' + port);
        });

        /**
         * Middleware
         */

        var is_not_logged = function(req, res, next) {
          var api_name = req.params.api;
          var session = req.session;
          var user = session.user;

          if (typeof user !== 'undefined') {
            res
              .status(401)
              .send({
                message: 'you are already logged in: log out first :('
              });
            return;
          }

          next();
        };

        var is_logged = function(req, res, next) {
          var api_name = req.params.api;
          var session = req.session;
          var user = session.user;

          if (typeof user === 'undefined') {
            res
              .status(401)
              .send({
                message: 'you aren\'t logged in: log in first :('
              });
            return;
          }

          next();
        };

        var is_authorized = function(req, res, next) {
          var api_name = req.params.api;
          var session = req.session;
          var apis = session.apis || {};
          var api = apis[api_name];

          if (typeof api === 'undefined' || typeof api.oauth_access_token_secret === undefined) {
            res
              .status(403)
              .send({
                message: 'unauthorized to use this API'
              });
            return;
          }

          next();
        };

        var is_allowed = [is_logged, is_authorized];

        /**
         * User
         */

        server.post('/api-oauth/user/login', is_not_logged, function(req, res) {
          var session = req.session;
          var body = req.body;
          var req_email = body.email;
          var req_password = body.password;
          var session_apis = session.apis || {};
          var db_apis;
          var db_api;
          var session_api;
          var api_name;
          var user;

          sa
            .get(apily_server + '/apily/0/app/' + application_name + '/user/by-email')
            .query({email: req_email})
            .end(function(err, sa_res) {
              if (err) {
                res.status(sa_res.statusCode).send('db comunication error');
                return;
              }

              user = sa_res.body;

              if (user.email === undefined) {
                res.send({
                  code: 10,
                  message: 'user unknown, please signup'
                });
                return;
              }

              if (req_password !== user.password) {
                res.send({
                  code: 11,
                  message: 'wrong passsword'
                });
                return;
              }

              session.user = {
                email: user.email,
                id: user._id,
                application: user.application
              };

              db_apis = user.apis || [];

              db_apis.forEach(function(db_api) {
                api_name = db_api.name;
                session_api = session_apis[api_name] = {};
                session_api.oauth_access_token = db_api.oauth_access_token;
                session_api.oauth_access_token_secret = db_api.oauth_access_token_secret;
                session_api.oauth_request_token = db_api.oauth_request_token;
                session_api.oauth_request_token_secret = db_api.oauth_request_token_secret;
                session_api.request_token_url = db_api.request_token_url;
                session_api.access_token_url = db_api.access_token_url;
                session_api.oauth_version = db_api.oauth_version;
                session_api.callback_url = db_api.callback_url;
                session_api.signature_method = db_api.signature_method;
                session_api.client_callback_url = db_api.client_callback_url;

                session_api.consumer_key = api_keys[api_name].consumer_key;
                session_api.consumer_secret = api_keys[api_name].consumer_secret;
              });

              session.apis = session_apis;

              res.send({
                code: 1,
                message: 'successfully logged in',
                session: session                     // TO-REMOVE
              });
            });
        });

        server.get('/api-oauth/user/logout', is_logged, function(req, res) {
          var session = req.session;
          delete session.user;
          delete session.apis;
          res.send({
            code: 1,
            message: 'successfully logged out',
            session: session                     // TO-REMOVE
          });
        });

        server.post('/api-oauth/user/signup', is_not_logged, function(req, res) {
          var session = req.session;
          var body = req.body;
          var email = body.email;
          var password = body.password;
          var password_confirm = body.password_confirm;

          if (password !== password_confirm) {
            res.status(401).send({
              message: 'password and password_confirm are different'
            });
            return;
          }

          sa
            .post(apily_server + '/apily/0/app/' + application_name + '/user')
            .send({
              email: email,
              password: password
            })
            .end(function(err, sa_res) {
              if (err) {
                res.status(sa_res.statusCode).send('db comunication error');
                return;
              }

              res.send({
                message: 'signed up as ' + email
              });
            });
        });

        server.get('/api-oauth/user/is-logged', is_logged, function (req, res) {
          res.send(req.session.user);
        });

        /**
         * API
         */

        server.get('/api-oauth/:api/is_authorized', is_allowed, function(req, res) {
          res.send({
            message: 'ok :)'
          });
        });

        server.get('/api-oauth/:api/is_authorized', is_logged, function(req, res) {
          var api_name = req.params.api;
          var session = req.session;
          var apis = session.apis || {};
          var api = apis[api_name];
          var result = {
            is_authorized = true;
          };

          if (typeof api === 'undefined' || typeof api.oauth_access_token_secret === undefined) {
            result.is_authorized = false;
          }

          res.send(result);
        });

        server.get('/api-oauth/:api/oauth', is_logged, function(req, res) {
          var api_name = req.params.api;
          var query = req.query;
          var request_token_url = query.request_token_url;
          var access_token_url = query.access_token_url;
          var authorize_url = query.authorize_url;
          var oauth_version = query.oauth_version || '1.0';
          var signature_method = query.signature_method || 'HMAC-SHA1';
          // if ccu is '/' it is not forwarded to this part of the server
          // static server will take care of it
          var client_callback_url = query.client_callback_url || '/api-oauth/end';
          var callback_url = req.headers.referer + 'api-oauth/' + api_name + '/callback';
          var consumer_key = api_keys[api_name].consumer_key;
          var consumer_secret = api_keys[api_name].consumer_secret;

          var session = req.session;
          var apis = session.apis || {};
          var api = apis[api_name] || {};

          session.apis = apis;
          apis[api_name] = api;

          // store the oauth info in the session
          api.request_token_url = request_token_url;
          api.access_token_url = access_token_url;
          api.consumer_key = consumer_key;
          api.consumer_secret = consumer_secret;
          api.oauth_version = oauth_version;
          api.callback_url = callback_url;
          api.signature_method = signature_method;
          api.client_callback_url = client_callback_url;

          // store the oauth info in the DB
          var user_id = session.user.id;
          var db_api = {};
          db_api.request_token_url = request_token_url;
          db_api.access_token_url = access_token_url;
          // db_api.consumer_key = consumer_key;
          // db_api.consumer_secret = consumer_secret;
          db_api.oauth_version = oauth_version;
          db_api.callback_url = callback_url;
          db_api.signature_method = signature_method;
          db_api.client_callback_url = client_callback_url;

          sa
            .post(apily_server + '/apily/0/user/' + user_id + '/api/' + api_name)
            .send(db_api)
            .end(function(err, sa_res) {
              if (err) {
                res.status(sa_res.statusCode).send('db comunication error');
                return;
              }

              var oa = new OAuth(
                request_token_url,
                access_token_url,
                consumer_key,
                consumer_secret,
                oauth_version,
                callback_url,
                signature_method
              );

              oa.getOAuthRequestToken(
                function (error, oauth_request_token, oauth_request_token_secret, results) {
                  if (error) {
                    console.log('error');
                    console.log(error);
                    return;
                  }

                  // store the access token in the DB
                  db_api = {};
                  db_api.oauth_request_token = oauth_request_token;
                  db_api.oauth_request_token_secret = oauth_request_token_secret;

                  sa
                    .post(apily_server + '/apily/0/user/' + user_id + '/api/' + api_name)
                    .send(db_api)
                    .end(function(err, sa_res_final) {
                      if (err) {
                        res.status(sa_res.statusCode).send('db comunication error');
                        return;
                      }

                      // store the access token in the session
                      api.oauth_request_token = oauth_request_token;
                      api.oauth_request_token_secret = oauth_request_token_secret;

                      // check if oauth_callback is mandatory
                      res.redirect(authorize_url +
                        '?oauth_token=' + oauth_request_token +
                        '&oauth_callback=' + callback_url);
                    });
                }
              );
            });
        });

        server.get('/api-oauth/:api/callback', /** is_logged, **/ function(req, res) {
          var api_name = req.params.api;
          var session = req.session;
          var apis = session.apis || {};
          var api = apis[api_name] || {};
          var user_id = session.user.id;
          var db_api = {};
          var consumer_key = api_keys[api_name].consumer_key;
          var consumer_secret = api_keys[api_name].consumer_secret;

          var oa = new OAuth(
            api.request_token_url,
            api.access_token_url,
            consumer_key,
            consumer_secret,
            api.oauth_version,
            api.callback_url,
            api.signature_method
          );

          session.apis = apis;
          apis[api_name] = api;

          oa.getOAuthAccessToken(
            api.oauth_request_token,
            api.oauth_request_token_secret,
            req.params['oauth_verifier'],
            function (error, oauth_access_token, oauth_access_token_secret, results) {
              if (error) {
                console.log('error in oauth authentication process: ');
                console.dir(error);
                return;
              }

              // store the access token in the DB
              db_api.oauth_access_token = oauth_access_token;
              db_api.oauth_access_token_secret = oauth_access_token_secret;

              sa
                .post(apily_server + '/apily/0/user/' + user_id + '/api/' + api_name)
                .send(db_api)
                .end(function(err, sa_res) {
                  if (err) {
                    res.status(sa_res.statusCode).send('db comunication error');
                    return;
                  }

                  // store the access token in the session
                  api.oauth_access_token = oauth_access_token;
                  api.oauth_access_token_secret = oauth_access_token_secret;


                  // note that endpoind could be decided client-side
                  res.redirect(api.client_callback_url);
                });
            }
          );
        });

        // could be unuseful
        server.get('/api-oauth/end', function(req, res) {
          res.send(req.session.user);
        });

        // 1. make group optional with regexp in route
        // 2. create a middleware to create an OAuth object
        // 3. on unknown http method send response with codified error number and message
        server.all('/api-oauth/:api/group/:group/endpoint/:endpoint', is_allowed, function(req, res) {
          var params = req.params;
          var api_name = params.api;
          var group_name = params.group;
          var endpoint_name = params.endpoint;
          var session = req.session;
          var apis = session.apis || {};
          var api = apis[api_name] || {};
          var url = req.query.url;
          var post_content_type;
          var post_body;
          var consumer_key = api_keys[api_name].consumer_key;
          var consumer_secret = api_keys[api_name].consumer_secret;

          var method = req.method.toLowerCase();

          var oa = new OAuth(
            api.request_token_url,
            api.access_token_url,
            consumer_key,
            consumer_secret,
            api.oauth_version,
            api.callback_url,
            api.signature_method
          );

          var callback = function(err, data, response) {
            var content_type = response.headers['content-type'];

            if (err) {
              res.status(response.statusCode).send(err);
              return;
            }

            res.set('Content-Type', content_type).send(data);
          };

          if (method === 'get' || method === 'delete') {
            oa[method](url, api.oauth_access_token, api.oauth_access_token_secret, callback);
            return;
          }

          if (method === 'post' || method === 'put') {
            post_content_type = req.get('content-type') || 'text/plain';
            post_body = req.body || req.text;
            oa[method](url, api.oauth_access_token, api.oauth_access_token_secret, post_body, post_content_type, callback);
            return;
          }
        });
      });
  });
};