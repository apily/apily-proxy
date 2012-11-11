/** rest server **/

var http = require('http');
var httpProxy = require('http-proxy');
var url = require('url');

exports.start = function(options) {
  var options =   options || {};
  var port = options.port || 8003;
  var suffix = '/api/';
  var proxy_options = {
    enable : {
      xforward: true
    },
    changeOrigin: true
  };

  httpProxy.createServer(proxy_options, function (req, res, proxy) {
    var parsed_url;
    var parsed_host;
    var parsed_port;

    req.url = req.url.replace(/\/api\//, '');
    parsed_url = url.parse(req.url);
    parsed_host = parsed_url.host;
    parsed_port = parsed_url.port || 80;
    proxy.proxyRequest(req, res, {
      host: parsed_host,
      port: parsed_port
    });

  }).listen(port, function() {
    console.log('Rest proxy listening on port ' + port);
  });
};