'use strict';
var nacl = require("tweetnacl");
var base64 = require("base64-js");

var encodeBase64 = base64.fromByteArray;
var decodeBase64 = base64.toByteArray;

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

var proto_encryption_provider = {
  newCredential: function(password) {
    //use combination of signing/encryption public keys for ID
    //also generate 
    var kp = nacl.sign.keyPair();
    var ep = nacl.box.keyPair();
    if(password !== undefined) {
       return {
	   'id': encodeBase64(kp.publicKey)+"_"+encodeBase64(ep.publicKey),
	   'locked': this.lockPassword( password, encodeBase64(kp.secretKey) + "_" + encodeBase64(ep.secretKey))
       };
      } else {
	  return {
	      'id': encodeBase64(kp.publicKey)+"_"+encodeBase64(ep.publicKey),
	      'sign': encodeBase64(kp.secretKey),
	      'encrypt': encodeBase64(ep.secretKey)
	  };
      };
  },
    addCredential: function(credential, password) {
	if(password !== undefined) {
	    var decode =this.unlockPassword(password,  credential.locked).split('_').map(decodeBase64);
	    //verify
	    if(encodeBase64(nacl.box.keyPair.fromSecretKey(decode[1]).publicKey) == credential.id.split("_")[1]) {
		this.keypairs[credential.id] = decode;
	    } else {
		throw "wrong password";
	    }
	} else { //assume not locked
	    this.keypairs[credential.id] = [decodeBase64(credential.sign), decodeBase64(credential.encrypt)];
	}
  },
  removeCredential: function(id) {
    delete this.keypairs[id];
  },
  encrypt: function(content, writer, readers) {
    var secret = this.keypairs[writer][1];
    content = toUTF8Array(JSON.stringify(content)); //bytearray
    var secret_key = nacl.randomBytes(nacl.secretbox.keyLength); //one time key for this encryption
    var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    content = encodeBase64(nacl.secretbox(content,nonce,secret_key));
    //for each reader - hand them an encrypted copy of the key
    var keys = [];
    var decrypt_info = toUTF8Array('naclbox-1:' + encodeBase64(secret_key));
    for(var i=0; i< readers.length; i++) {
      keys.push(encodeBase64(nacl.box(decrypt_info,nonce,decodeBase64(readers[i].split('_')[1]),secret)));
    }
    return "naclbox-1:" + writer + ":" + encodeBase64(nonce) + ":" + keys.join(",") + ":" + content;
  },
  decrypt: function(encrypted, potential_readers) {
    encrypted = encrypted.split(":");
    if(encrypted[0] !== "naclbox-1") throw "Invalid encrypted type";
    //have to try potential_readers against encrypted keys
    var writer_public = decodeBase64(encrypted[1].split("_")[1]);
    var nonce = decodeBase64(encrypted[2]);
    var encrypted_keys = encrypted[3].split(',').map(decodeBase64);
    if(!potential_readers) potential_readers = Object.keys(this.keypairs);
    for(var i=0; i< encrypted_keys.length; i++) {
      for(var j=0; j< potential_readers.length; j++) {
        var secret = this.keypairs[potential_readers[j]][1];
        var key = nacl.box.open(encrypted_keys[i], nonce, writer_public, secret);
        if(key) {
          key = decodeBase64(UTF8ArrayToStr(key).split(":")[1]);
          break;
        }
      }
    }
    if(key) {
      var value = nacl.secretbox.open(decodeBase64(encrypted[4]), nonce, key);
      value = UTF8ArrayToStr(value);
      return JSON.parse(value);
    }
    return null;
  },
  passkey: function(password, nonce) {
      //todo: eval multihash to make cracking more difficult
      var hash = nacl.hash(toUTF8Array(password + nonce));
      var pk = hash.slice(0,nacl.secretbox.keyLength);
      return pk
  },
  lockPassword: function(password, string) {
      var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
      return encodeBase64(nonce) + "_" + encodeBase64(nacl.secretbox(toUTF8Array(string), nonce, this.passkey(password, encodeBase64(nonce))));
  },
  unlockPassword: function(password, string) {
      var nonce = string.split('_')[0];
      var pk = this.passkey(password, nonce);
      var decode = nacl.secretbox.open(decodeBase64(string.split('_')[1]), decodeBase64(nonce), pk);
      if(decode) return UTF8ArrayToStr(decode);
      throw "wrong password";
  },
  sign: function(owners, hashedDoc) {   //should return promise for signature
          //find a keypair for which we have the secret 
    for(var i=0; i< owners.length; i++) {
      var owner = owners[i];
      var secret = this.keypairs[owner];
      if(secret) {
        secret = secret[0];
        break;
      }
    }
    if(!secret) {
      console.log("owners",owners);
      throw "No owners found";
    }
    if(typeof hashedDoc == "string") hashedDoc = toUTF8Array(hashedDoc);
    return Promise.resolve( secret ? ("ed25519-1:" + owner + ":" + encodeBase64(nacl.sign.detached(hashedDoc,secret))) : "");
  },
  verify: function(hashedDoc, sig) {
    sig = sig.split(":");
    if(sig[0] !== "ed25519-1") throw "Invalid signature type";
    if(typeof hashedDoc == "string") hashedDoc = toUTF8Array(hashedDoc);
    return nacl.sign.detached.verify(hashedDoc, decodeBase64(sig[2]), decodeBase64(sig[1].split('_')[0])) ? sig[1] : null;
  },
  hash: function(a) { return a; } //don't bother with hashing 
};

function encryptionProvider() {
  return Object.assign({keypairs : {}}, proto_encryption_provider);
}

exports.encryptionProvider = encryptionProvider;
