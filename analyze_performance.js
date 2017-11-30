var lineReader = require('readline');
var fs = require('fs');
var Path = require('path');

//
// CONFIGURATION
//  You can change the values in this section to control the output
//

// this controls the number of top X entries that will be included in the results.
var topCount = 10;

// only files that are at least this big will be included in calculating bandwidth. Small files can skew
// the results because they download so quickly that it's impossible to calculate a true rate.
var rateSizeThreshold = 1024 * 1024; // 1 MB

//
// CODE
//  Everything past this point is code for doing the analysis. You shouldn't need to change any of this unless you
//  want to extend the script
//
console.log('');
console.log('* This script will analyze the SMB and HTTP traffic in the AEM Desktop log files and produce');
console.log('* summary information based on this data. It may take some time to run depending on the ');
console.log('* size of the logs.');
console.log('');
if (!process.argv[2]) {
  console.log('USAGE: node analyze_performance.js [path to log directory]');
  return;
}

var logDir = process.argv[2];
var cmdLog = Path.join(logDir, 'smb-cmd.log');
var reqLog = Path.join(logDir, 'smb-request.log');

var readerCount = 2;

var cmdLogReader = fs.createReadStream(cmdLog);
var reqLogReader = fs.createReadStream(reqLog);

var cmdReader = lineReader.createInterface({
  input: cmdLogReader
});

var reqReader = lineReader.createInterface({
  input: reqLogReader
});

var logStart = false; // date of the first log entry
var logEnd = false; // date of the last log entry
var cmds = {}; // stores each smb cmd so that start/stop can be mapped
var reqs = {}; // stores each http request so that start/stop can be mapped
var runtimes = {}; // stores the total runtime for each smb command type
var reqRuntimes = {}; // stores the total runtime for each http request method
var cmdStatus = {}; // stores the total count of each smb status that's returned
var reqStatus = {}; // stores the total count of each http status code that's returned
var totalCommands = 0; // the total number of smb commands
var totalRequests = 0; // the total number of http requests
var totalRequestsUnknown = 0; // total number of http requests with an unknown format
var totalStartless = 0; // number of smb commands without a begin entry
var totalReqStartless = 0; // number of http commands with a begin entry
var totalNotifications = 0; // number of notifications sent by smb server
var longRunningCmds = []; // running list of the top longest running smb commands
var longRunningReqs = []; // running list of the top longest running http requests
var bandwidths = []; // list of all bandwidth samples captured
var lowestBandwidths = []; // list of the lowest bandwidth rates observed
var topCommandsByPath = {}; // lookup of all command/path combinations
var topRequestsByUrl = {}; // looukp of all method/url combinations

/**
 * Parses a standard log message and breaks it into common elements like timestamp, id, level, message, etc.
 * @param {string} message The raw log message to parse.
 * @returns {object} An object containing the message's common elements. Will be falsy if the message is not in a
 *  recognized format.
 */
function parseLogMessage(message) {
  var regex = /^([^ ]+)\s-\s([^ ]+)\s([^ ]+)\s([^ ]+)\s([^ ]+)\s(.+)$/g;
  var match = regex.exec(message);
  if (match) {
    return {
      timestamp: Date.parse(match[1]),
      level: match[2],
      log: match[3],
      context: match[4],
      id: match[5],
      message: match[6]
    };
  } else {
    return false;
  }
}

/**
 * Adds a value to a list of top highest/lowest values.
 * @param {array} topCounts Current list of top values. The array will be modified in place and is not guaranteed to be sorted.
 * @param {object} logData Data for the log entry to which the count belongs.
 * @param {integer} count The count to add.
 * @param {boolean} ascending If true, the lowest values will be in the count array. Otherwise the highest values.
 */
function addTopCount(topCounts, logData, count, ascending) {
  if (topCounts.length < topCount) {
    topCounts.push({data: logData, count: count});
  } else {
    var difference = 0;
    var toSwap = -1;
    for (var i = 0; i < topCounts.length; i++) {
      if ((!ascending && count - topCounts[i].count > difference) ||
           (ascending && count - topCounts[i].count < difference)) {
        toSwap = i;
      }
    }
    if (toSwap >= 0) {
      topCounts[toSwap] = {data: logData, count: count};
    }
  }
}

/**
 * Increments the running count for a status entry.
 * @param {object} lookup Object containing the current status counts.
 * @param {string} status The status whose count will be incremented.
 */
function addStatus(lookup, status) {
  if (!lookup[status]) {
    lookup[status] = 0;
  }
  lookup[status]++;
}

/**
 * Converts a single-level object to an array whose entries are an object containing key/value pairs.
 * @param {object} obj The object to convert.
 * @param {function} valueFunc If specified, will be called when retrieving the value for an entry. The function should
 *  take one argument (the current value) and return the value that should be stored in the array.
 * @returns {Array} The converted object. Each entry will be an object in the form {key: <item key>, value: <item value>}.
 */
function objectToArray(obj, valueFunc) {
  if (!valueFunc) {
    valueFunc = function (value) {
      return value;
    };
  }
  var result = [];
  for (var key in obj) {
    if (obj.hasOwnProperty(key)) {
      result.push({key: key, value: valueFunc(obj[key])});
    }
  }
  return result;
}

/**
 * Sorts an array (in place) produced by objectToArray so that it's sorted in descending order by value.
 * @param {array} toSort The array to sort.
 */
function sortArrayedObject(toSort) {
  toSort.sort(function (a, b) {
    if (a.value > b.value) {
      return -1;
    }
    if (a.value < b.value) {
      return 1;
    }
    return 0;
  });
}

/**
 * Adds a runtime to a running list of runtimes.
 * @param {object} times The running list of times. The log's description value will be used as keys.
 * @param {object} starts An object containing the start entries for a command/request sequence.
 * @param {object} log The log data whose timestamp and description will be used to calculate and store runtime.
 * @returns {number} The runtime for the command/request.
 */
function addRuntime(times, starts, log) {
  if (!times[log.description]) {
    times[log.description] = {
      runtime: 0,
      count: 0
    };
  }
  var runtime = log.timestamp - starts[log.id].timestamp;
  times[log.description].runtime += runtime;
  times[log.description].count++;
  return runtime;
}

cmdLogReader.on('error', function (err) {
  console.log('******** smb-cmd.log not found ********');
  readerCount--;
});

reqLogReader.on('error', function (err) {
  console.log('******** smb-request.log not found ********');
  readerCount--;
});

cmdReader.on('line', function (line) {
  var log = parseLogMessage(line);
  if (log) {
    if (!logStart) {
      logStart = log.timestamp;
    }
    logEnd = log.timestamp;
    // parse additional information about the command from the log message
    var regex = /^([-<>]+)\s([^{]*)(.+)$/g;
    var match = regex.exec(log.message);
    if (match) {
      log['cmd'] = JSON.parse(match[3]);
      if (!log.cmd.fileName) {
        log.cmd['fileName'] = '<no path>';
      }
      log['description'] = log.cmd.commandName;
      log['path'] = log.cmd.fileName;
      log['cmdstatus'] = match[2];
      var direction = match[1];
      if (direction == '->') {
        totalCommands++;
        cmds[log.id] = log;
        addStatus(topCommandsByPath, log.description + ':' + log.path);
      } else if (cmds[log.id]) {
        var runtime = addRuntime(runtimes, cmds, log);
        addTopCount(longRunningCmds, log, runtime);
        addStatus(cmdStatus, log.cmdstatus);
        delete cmds[log.id];
      } else {
        // response without a request?
        totalCommands++;
        if (log.cmd.commandName != 'nt_transact_notify_change') {
          // it's a command without a "Begin" entry
          totalStartless++;
          addStatus(cmdStatus, log.cmdstatus);
        } else {
          // it's an SMB notification, which doesn't have a begin entry
          totalNotifications++;
        }
      }
    }
  }
});
cmdReader.on('close', closeReader);

reqReader.on('line', function (line) {
  var log = parseLogMessage(line);
  if (log) {
    // parse additional information about the request from the message
    var regex = /^([^ ]+)\s([^ ]+)\s(([0-9]+)\s)?([^ ]+)\s(.+)$/g;
    var match = regex.exec(log.message);
    if (match) {
      var direction = match[2];
      log['request'] = {
        url: match[6],
        method: match[5],
        statusCode: match[4]
      };
      log['description'] = log.request.method;

      // convert the url into a friendly path
      var path = decodeURI(log.request.url);
      var apiAssets = '/api/assets';
      var apiAssetsIndex = path.indexOf(apiAssets);
      if (apiAssetsIndex >= 0) {
        path = path.substr(apiAssetsIndex + apiAssets.length);
      }

      log['path'] = path;
      if (direction == '->') {
        totalRequests++;
        reqs[log.id] = log;
        addStatus(topRequestsByUrl, log.description + ':' + log.path);
      } else if (direction == '<-') {
        // for responses, parse transfer size from the message
        var statRegex = /^(.+)\s\[(.+)\]\[(.+)\]\[(.+)b\]\[.+\]$/g;
        var stats = statRegex.exec(path);
        var useBandwidth = true;

        if (!stats) {
          // not all responses have a transfer size
          statRegex = /^(.+)\s\[(.+)\]\[(.+)\]$/g;
          stats = statRegex.exec(path);
          useBandwidth = false;
        }

        if (stats) {
          log['path'] = stats[1];
        }

        if (reqs[log.id]) {
          var runtime = addRuntime(reqRuntimes, reqs, log);
          addTopCount(longRunningReqs, log, runtime);
          addStatus(reqStatus, log.request.statusCode);
          delete reqs[log.id];

          // capture some rate information
          if (stats && useBandwidth) {
            if (stats[4]) {
              // ignore json requests, since we're more concerned with binary transfer speeds
              if (log.path.indexOf('.json?limit=') < 0) {
                // only include binaries that are at least a given size. Small binaries can skew the numbers
                // because they happen so quickly that a proper transfer speed can't be calculated
                if (stats[4] >= rateSizeThreshold) {
                  var currBandwidth = Math.round(stats[4] / runtime);
                  bandwidths.push(currBandwidth);
                  addTopCount(lowestBandwidths, log, currBandwidth, true);
                }
              }
            }
          }
        } else {
          // response without a request
          totalRequests++;
          totalReqStartless++;
          addStatus(reqStatus, log.request.statusCode);
        }
      } else {
        // unhandled message format
        totalRequestsUnknown++;
      }
    }
  }
});

reqReader.on('close', closeReader);

var closeCount = 0;

/**
 * Prints information from a set of running totals.
 * @param {string} description Arbitrary value to print with messages to distinguish between sections.
 * @param {object} incomplete Entity containing incomplete records.
 * @param {object} times Entity containing transfer times by type.
 * @param {object} status Entity containing results by count.
 * @param {array} longRunning List of longest running items.
 * @param {object} topEntries Lookup of the number of operation types per path
 */
function printStatus(description, incomplete, times, status, longRunning, topEntries) {
  console.log('');
  console.log('************************************');
  console.log('%s SUMMARY DATA', description);
  console.log('************************************');
  console.log('');
  console.log('INCOMPLETE ' + description + 'S');
  console.log('------------------------------------');
  for (var cmd in incomplete) {
    var currCmd = incomplete[cmd];
    console.log('%s %s %s', currCmd.id, currCmd.description, currCmd.path);
  }
  console.log('');
  console.log('AVG ' + description + ' RUNTIME');
  console.log('------------------------------------');
  var runtimeArr = objectToArray(times, function (value) {
    return Math.round(value.runtime / value.count);
  });
  sortArrayedObject(runtimeArr);
  for (var i = 0; i < runtimeArr.length; i++) {
    var cmd = runtimeArr[i];
    console.log('%s %sms', cmd.key, cmd.value);
  }
  console.log('');
  console.log(description + ' COUNTS');
  console.log('------------------------------------');
  var countArr = objectToArray(times, function (value) {
    return value.count;
  });
  sortArrayedObject(countArr);
  for (var i = 0; i < countArr.length; i++) {
    var cmd = countArr[i];
    console.log('%s %s', cmd.key, cmd.value);
  }
  console.log('');
  console.log(description + ' RESULT COUNTS');
  console.log('------------------------------------');
  var resultArr = objectToArray(status);
  sortArrayedObject(resultArr);
  for (var i = 0; i < resultArr.length; i++) {
    var result = resultArr[i]
    console.log('%s %s', result.key, result.value);
  }
  console.log('');
  console.log('TOP %s ' + description + 'S WITH LONGEST RUNTIME', longRunning.length);
  console.log('------------------------------------');
  longRunning.sort(function (a, b) {
    if (a.count > b.count) {
      return -1;
    }
    if (a.count < b.count) {
      return 1;
    }
    return 0;
  });
  for (var i = 0; i < longRunning.length; i++) {
    var currCmd = longRunning[i];
    console.log('%s %s %s %sms', currCmd.data.id, currCmd.data.description, currCmd.data.path, currCmd.count);
  }
  console.log('');
  console.log('TOP %s DUPLICATED %sS', topCount, description);
  console.log('------------------------------------');
  var duplicateArr = objectToArray(topEntries);
  sortArrayedObject(duplicateArr);
  for (var i = 0; i < duplicateArr.length; i++) {
    if (i >= topCount) {
      break;
    }
    console.log('%s %s', duplicateArr[i].key, duplicateArr[i].value);
  }
}

function closeReader() {
  closeCount++;

  // make sure both log files have finished
  if (closeCount == readerCount) {
    var bandwidthStr = 'N/A';
    if (bandwidths.length) {
      var bandwidth = 0;
      for (var i = 0; i < bandwidths.length; i++) {
        bandwidth += bandwidths[i];
      }

      bandwidth /= bandwidths.length;
      // convert to bytes per second
      bandwidth *= 1000;
      // convert to kilobytes per second
      bandwidthStr = Math.round(bandwidth / 1024) + ' KB/s';
    }

    var elapsed = logEnd - logStart;
    var elapsedMinutes = Math.round(elapsed / 1000 / 60);
    console.log('************************************');
    console.log('SUMMARY');
    console.log('************************************');
    console.log('date range: %s - %s', new Date(logStart), new Date(logEnd));
    console.log('elapsed minutes: %s', elapsedMinutes);
    console.log('total smb commands: %s', totalCommands);
    console.log('smb commands per minute: %s', Math.round(totalCommands / elapsedMinutes));
    console.log('total smb commands without begin: %s', totalStartless);
    console.log('total smb notifications sent: %s', totalNotifications);
    console.log('total http requests: %s', totalRequests);
    console.log('http requests per minute: %s', Math.round(totalRequests / elapsedMinutes));
    console.log('total http requests without begin: %s', totalReqStartless);
    console.log('total http requests with unknown format: %s', totalRequestsUnknown);
    console.log('average bandwidth: %s', bandwidthStr);
    console.log('   (%s occurrences greater than %s bytes sampled)', bandwidths.length, rateSizeThreshold);
    printStatus('SMB COMMAND', cmds, runtimes, cmdStatus, longRunningCmds, topCommandsByPath);
    printStatus('HTTP REQUEST', reqs, reqRuntimes, reqStatus, longRunningReqs, topRequestsByUrl);
    console.log('');
    console.log('LOWEST BANDWIDTH OBSERVED');
    console.log('------------------------------------');
    lowestBandwidths.sort(function (a, b) {
      if (a.count < b.count) {
        return -1;
      }
      if (a.count > b.count) {
        return 1;
      }
      return 0;
    });
    for (var i = 0; i < lowestBandwidths.length; i++) {
      var currCmd = lowestBandwidths[i];
      var bandwidthValue = currCmd.count;
      bandwidthValue *= 1000;
      bandwidthValue = Math.round(bandwidthValue / 1024);
      console.log('%s %s %s %s %s KB/sec', currCmd.data.id, new Date(currCmd.data.timestamp), currCmd.data.description, currCmd.data.path, bandwidthValue);
    }
  }
}
