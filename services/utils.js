var properties = require(__dirname + '/../properties/properties');
var CryptoJS = require('crypto-js');
var logger = require(__dirname + '/../services/logger').getInstance();

exports.get_hash = function(uid) {
    var d = new Date();
    var d2 = new Date();
    
    var present_salt=d.getUTCDate()+d.getUTCHours().toString();
    //calcul de la date - 1h (3600000 millisecondes)
    d2.setTime(d.getTime()-3600000);
    var past_salt=d2.getUTCDate()+d2.getUTCHours().toString();

    //calcul de la date + 1h
    d2.setTime(d.getTime()+3600000);
    var next_salt=d2.getUTCDate()+d2.getUTCHours().toString();

    logger.debug("past_salt,present_salt,next_salt :"+past_salt+","+present_salt+","+next_salt);


    var present_hash = CryptoJS.SHA256(CryptoJS.MD5(properties.getEsupProperty('users_secret')).toString()+uid+present_salt).toString();
    var next_hash = CryptoJS.SHA256(CryptoJS.MD5(properties.getEsupProperty('users_secret')).toString()+uid+next_salt).toString();
    var past_hash = CryptoJS.SHA256(CryptoJS.MD5(properties.getEsupProperty('users_secret')).toString()+uid+past_salt).toString();

    var hashes = [past_hash, present_hash, next_hash];

    logger.debug("hashes for "+uid+": "+hashes);

    return hashes;
}

exports.cover_string = function(str, start, end) {
    if (str.length <= (start + end)) return str;
    var start_str = str.substr(0, start);
    var end_str = str.substr(str.length - (end + 1), str.length - 1);
    var middle_str = '';
    for (var i = 0; i < str.length - (start + end); i++) {
        middle_str += '*';
    }
    return start_str + middle_str + end_str;
}


exports.generate_string_code = function(code_length) {
    var crypto = require('crypto');
    return crypto.randomBytes(code_length / 2).toString('hex');
}
exports.generate_digit_code = function(code_length) {
    return Math.random().toString().substr(2, code_length);
}

exports.generate_u8array_code = function(nonce_length) {
	const crypto = require('crypto');
	return crypto.randomBytes(nonce_length).buffer;
}

exports.check_transport_validity= function(transport, value){
    var reg;
    if (transport == 'sms') reg = new RegExp("^0[6-7]([-. ]?[0-9]{2}){4}$");
    else reg = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
    return reg.test(value);
}

exports.getFileName= function(filename){
    return filename.split(global.base_dir)[1];
}

exports.get_auth_bearer = function (headers) {
    return (headers.authorization.match(/^Bearer (.*)/) || [])[1]
}




/**
 * Convert from a Base64URL-encoded string to an Array Buffer. Best used when converting a
 * credential ID from a JSON string to an ArrayBuffer, like in allowCredentials or
 * excludeCredentials
 *
 * Helper method to compliment `bufferToBase64URLString`
 *
 * source: https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/src/helpers/base64URLStringToBuffer.ts .
 */
exports.base64URLStringToBuffer = function(base64URLString) {
  // Convert from Base64URL to Base64
  const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
  /**
   * Pad with '=' until it's a multiple of four
   * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
   * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
   * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
   * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
   */
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64.padEnd(base64.length + padLength, '=');

  // Convert to a binary string
  const binary = atob(padded);

  // Convert binary string to buffer
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return buffer;
}


/**
 * Convert the given array buffer into a Base64URL-encoded string. Ideal for converting various
 * credential response ArrayBuffers to string for sending back to the server as JSON.
 *
 * Helper method to compliment `base64URLStringToBuffer`
 *
 * source: https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/src/helpers/bufferToBase64URLString.ts .
 */
exports.bufferToBase64URLString = function(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
