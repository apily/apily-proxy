/* !
 * apily-proxy
 * the same-origin poly crashier
 * Copyright (c) 2012 Enrico Marino e Federico Spini for Apily (https://github.com/apily)
 * MIT License
 */

 !(function (exports) {

  /**
   * Library version.
   */

  exports.version = '0.0.1';

  exports.start = function () {
    var http = require('http');
    var httpProxy = require('http-proxy');

    var server = {};
    server.static = require('./server-static.js');
    server.oauth = require('./server-oauth.js');
    server.rest = require('./server-rest.js');

    var port = {
      front: 8000,
      static: 8001,
      oauth: 8002,
      rest: 8003
    };

    server.static.start({
      port: port.static,
      public: 'public'
    });

    server.oauth.start({
      port: port.oauth,
      front_port: port.front,
      // apily_server: 'localhost:3000'
    });

    server.rest.start({
      port: port.rest
    });

    var options = {
      enable : {
        xforward: true
      },
      changeOrigin: true,
    };

    httpProxy.createServer(options, function (req, res, proxy) {
      if (req.url.match(/^\/api\//)) {
        console.log('/api/ request');
        proxy.proxyRequest(req, res, {
          host: 'localhost',
          port: port.rest
        });
      } else if (req.url.match(/^\/api-oauth\//)) {
        console.log('/api-oauth/ request');
        proxy.proxyRequest(req, res, {
          host: 'localhost',
          port: port.oauth
        });
      } else {
        console.log('static request');
        proxy.proxyRequest(req, res, {
          host: 'localhost',
          port: port.static
        });
      }
    }).listen(port.front, function() {
      console.log('Front server listening on port ' + port.front);
    });
  }
}(this));
