/** static server **/

var connect = require('connect');

exports.start = function(options) {
  var options = options ||{};
  var port = options.port || 8001;
  var public = options.static || 'public';
  var app_static = connect()
    .use(connect.favicon())
    .use(connect.logger('dev'))
    .use(connect.static(public))
    .listen(port, function() {
      console.log('Static server listening on port ' + port);
    });  
};


