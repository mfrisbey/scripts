var http = require('http');
var request = require('request');
var fs = require('fs');
var URL = require('url');
const { spawn } = require('child_process');
var Path = require('path');

if (process.argv.length < 4) {
  console.log('USAGE: node testbandwidth.js [url] [login-token]');
} else {
  var url = process.argv[2];
  var parsedUrl = URL.parse(url);
  var fileName = url.substr(url.lastIndexOf('/') + 1);
  var loginToken = process.argv[3];
  var headers = {
    cookie: 'login-token=' + loginToken
  }

  function monitorResponse(description, res, cb) {
    console.log('%s response code %d', description, res.statusCode);
    var start = new Date().getTime();
    var size = 0;
    res.on('data', function (chunk) {
      size += chunk.length;
    });

    res.on('end', function () {
      var end = new Date().getTime();
      var elapsed = end - start;
      var rate = Math.round(size / elapsed);
      rate *= 1000;
      rate = Math.round(rate / 1024);
      console.log('%s downloaded %d bytes in %d ms. %d KB/s', description, size, elapsed, rate);
      cb();
    });
  }

  function testRequest(cb) {
    var options = {
      url: url,
      headers: headers
    };

    var req = request(options);

    req.on('error', function (err) {
      console.log('ERROR', err);
    });
    req.on('response', function (res) {
      monitorResponse('request', res, cb);
    });

    req.pipe(fs.createWriteStream('request_' + fileName));
  }

  function testHttp(cb) {
    var options = parsedUrl;
    options['headers'] = headers;
    http.request(options, function (res) {
      monitorResponse('http', res, cb);
      res.pipe(fs.createWriteStream('http_' + fileName));
    }).end();
  }

  function getBuffer(buffer) {
    if (buffer) {
      if (buffer instanceof Buffer) {
        return buffer.toString('utf8');
      } else {
        return buffer;
      }
    }
    return '';
  }

  function testCurl(cb) {
    var child = spawn('curl', ['-H', 'Cookie: login-token=' + loginToken, '-o', Path.join(__dirname, 'curl_' + fileName), url]);
    var stdOut = '';
    var stdErr = '';
    child.stdout.on('data', function (chunk) {
      stdOut += getBuffer(chunk);
    });
    child.stderr.on('data', function (chunk) {
      stdErr += getBuffer(chunk);
    });
    child.on('close', function (code) {
      console.log('* STDOUT *');
      console.log(stdOut);
      console.log('* STDERR *');
      console.log(stdErr);
      console.log('curl ended with code %s', code);
      cb();
    });
    child.on('error', function (err) {
      console.log('STREAMING ERROR', err);
    });
  }

  console.log('testing request module...');
  console.log('------------------------------');
  testRequest(function () {
    console.log('');
    console.log('testing http module...');
    console.log('------------------------------');
    testHttp(function () {
      console.log('');
      console.log('testing curl...');
      console.log('------------------------------');
      testCurl(function () {
        console.log('finished');
      });
    });
  });
}
