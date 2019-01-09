'use strict';
var nacl = require("tweetnacl");
var base64 = require("base64-js");

function toUTF8Array(str) {
  var utf8 = [];
  for (var i = 0; i < str.length; i++) {
    var charcode = str.charCodeAt(i);
    if (charcode < 0x80) utf8.push(charcode);
    else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    } else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(
        0xe0 | (charcode >> 12),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f)
      );
    }
    // surrogate pair
    else {
      i++;
      // UTF-16 encodes 0x10000-0x10FFFF by
      // subtracting 0x10000 and splitting the
      // 20 bits of 0x0-0xFFFFF into two halves
      charcode =
        0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      utf8.push(
        0xf0 | (charcode >> 18),
        0x80 | ((charcode >> 12) & 0x3f),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f)
      );
    }
  }
  return new Uint8Array(utf8);
}

function UTF8ArrayToStr(array) {
  var out, i, len, c;
  var char2, char3;

  out = "";
  len = array.length;
  i = 0;
  while (i < len) {
    c = array[i++];
    switch (c >> 4) {
      case 0:
      case 1:
      case 2:
      case 3:
      case 4:
      case 5:
      case 6:
      case 7:
        // 0xxxxxxx
        out += String.fromCharCode(c);
        break;
      case 12:
      case 13:
        // 110x xxxx   10xx xxxx
        char2 = array[i++];
        out += String.fromCharCode(((c & 0x1f) << 6) | (char2 & 0x3f));
        break;
      case 14:
        // 1110 xxxx  10xx xxxx  10xx xxxx
        char2 = array[i++];
        char3 = array[i++];
        out += String.fromCharCode(
          ((c & 0x0f) << 12) | ((char2 & 0x3f) << 6) | ((char3 & 0x3f) << 0)
        );
        break;
    }
  }
  return out;
}

//function toHexString(byteArray) {
//  return Array.prototype.map.call(byteArray, function(byte) {
//    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
//  }).join('');
//}

//function toByteArray(hexString) {
//  var i;
//  var result = new Uint8Array(hexString.length/2);
//  for(i=0; i< hexString.length; i+= 2) {
//    result[i/2] = parseInt(hexString.substring(i, i+2), 16);
//  }
//  return result;
//}

var signing_provider = {
  keypairs : {},
  newCredential: function() {
    var kp = nacl.sign.keypair();
    return [base64.fromByteArray(kp.publicKey), kp.secretKey];
  },
  addCredential: function(credential) {
    this.keypairs[credential[0]] = credential[1];
  },
  sign: function(owners, hashedDoc) {   //should return promise for signature
    //find a keypair for which we have the secret 
    for(var i=0; i< owners.length; i++) {
      var owner = owners[i];
      var secret = this.keypairs[owner];
      if(secret) break;
    }
    if(!secret) throw "No owners found";
    if(typeof hashedDoc == "string") hashedDoc = toUTF8Array(hashedDoc);
    return Promise.resolve( secret ? ("ed25519-1:" + owner + ":" + base64.fromByteArray(nacl.sign.detached(hashedDoc,secret))) : "");
  },
  verify: function(hashedDoc, sig) {
    sig = sig.split(":");
    if(sig[0] !== "ed25519-1") throw "Invalid signature type";
    if(typeof hashedDoc == "string") hashedDoc = toUTF8Array(hashedDoc);
    return nacl.sign.detached.verify(hashedDoc, base64.toByteArray(sig[2]), base64.toByteArray(sig[1])) ? sig[1] : null;
  },
  hash: function(a) { return a; } //don't bother with hashing 
};
exports.signing_provider = signing_provider;
