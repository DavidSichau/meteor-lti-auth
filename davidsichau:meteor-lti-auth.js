// Write your package code here!
var crypto,
    exports,
    fs,
    https,
    request,
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

var EXPIRE_IN_SEC = 5 * 60;

fs = Npm.require('fs');
https = Npm.require('https');
crypto = Npm.require('crypto');

// NonceStore

var NonceStore = (function() {

    function NonceStore() {
        this.setUsed = __bind(this.setUsed, this);
        this.isNew = __bind(this.isNew, this);
    }

    NonceStore.prototype.isNonceStore = function() {
        return true;
    };

    NonceStore.prototype.isNew = function() {
        var arg, i;
        for (i in arguments) {
            arg = arguments[i];
            if (typeof arg === 'function') {
                return arg(new Error("NOT IMPLEMENTED"), false);
            }
        }
    };

    NonceStore.prototype.setUsed = function() {
        var arg, i;
        for (i in arguments) {
            arg = arguments[i];
            if (typeof arg === 'function') {
                return arg(new Error("NOT IMPLEMENTED"), false);
            }
        }
    };

    return NonceStore;

})();


// MemoryNonceStore

var MemoryNonceStore = (function(_super) {

    __extends(MemoryNonceStore, _super);

    function MemoryNonceStore(consumer_key) {
        this.used = [];
    }

    MemoryNonceStore.prototype.isNew = function(nonce, timestamp, next) {
        var firstTimeSeen;
        if (next == null) {
            next = function() {};
        }
        if (typeof nonce === 'undefined' || nonce === null || typeof nonce === 'function' || typeof timestamp === 'function' || typeof timestamp === 'undefined') {
            return next(new Error('Invalid parameters'), false);
        }
        firstTimeSeen = this.used.indexOf(nonce) === -1;
        if (!firstTimeSeen) {
            return next(new Error('Nonce already seen'), false);
        }
        return this.setUsed(nonce, timestamp, function(err) {
            var currentTime, timestampIsFresh;
            if (typeof timestamp !== 'undefined' && timestamp !== null) {
                currentTime = Math.round(Date.now() / 1000);
                timestampIsFresh = (currentTime - parseInt(timestamp, 10)) <= EXPIRE_IN_SEC;
                if (timestampIsFresh) {
                    return next(null, true);
                } else {
                    return next(new Error('Expired timestamp'), false);
                }
            } else {
                return next(new Error('Timestamp required'), false);
            }
        });
    };

    MemoryNonceStore.prototype.setUsed = function(nonce, timestamp, next) {
        if (next == null) {
            next = function() {};
        }
        this.used.push(nonce);
        return next(null);
    };

    return MemoryNonceStore;

})(NonceStore);


// HMAC_SHA1

var special_encode = function(string) {
    return encodeURIComponent(string).replace(/[!'()]/g, escape).replace(/\*/g, "%2A");
};

var _clean_request_body = function(body) {
    var key, out, val;
    out = [];
    if (typeof body !== 'object') {
        return body;
    }
    for (key in body) {
        val = body[key];
        if (key === 'oauth_signature') {
            continue;
        }
        out.push("" + key + "=" + (special_encode(val)));
    }
    return special_encode(out.sort().join('&'));
};

var HMAC_SHA1 = (function() {

    function HMAC_SHA1() {}

    HMAC_SHA1.prototype.toString = function() {
        return 'HMAC_SHA1';
    };

    HMAC_SHA1.prototype.build_signature_base_string = function(req, consumer_secret, token) {
        var hitUrl, key, raw, sig;
        hitUrl = req.headers["x-forwarded-proto"] + '://' + req.headers.host + req.url;
        sig = [req.method.toUpperCase(), special_encode(hitUrl), _clean_request_body(req.body)];
        key = "" + consumer_secret + "&";
        if (token) {
            key += token;
        }
        raw = sig.join('&');
        return [key, raw];
    };

    HMAC_SHA1.prototype.build_signature = function(req, consumer_secret, token) {
        var cipher, hashed, key, raw, _ref;
        _ref = this.build_signature_base_string(req, consumer_secret, token), key = _ref[0], raw = _ref[1];
        cipher = crypto.createHmac('sha1', key);
        return hashed = cipher.update(raw).digest('base64');
    };

    return HMAC_SHA1;

})();


// Provider

Provider = (function() {

    Provider.prototype.body = {};

    function Provider(consumer_key, consumer_secret, nonceStore, signature_method) {
        if (signature_method == null) {
            signature_method = new HMAC_SHA1();
        }
        this.parse_request = __bind(this.parse_request, this);

        this.valid_request = __bind(this.valid_request, this);

        if (typeof consumer_key === 'undefined' || consumer_key === null) {
            throw new Error('Must specify consumer_key');
        }
        if (typeof consumer_secret === 'undefined' || consumer_secret === null) {
            throw new Error('Must specify consumer_secret');
        }
        if (!nonceStore) {
            nonceStore = new MemoryNonceStore(consumer_key);
        }
        if (!(typeof nonceStore.isNonceStore === "function" ? nonceStore.isNonceStore() : void 0)) {
            throw new Error('Fourth argument must be a nonceStore object');
        }
        this.consumer_key = consumer_key;
        this.consumer_secret = consumer_secret;
        this.signer = signature_method;
        this.nonceStore = nonceStore;
    }

    Provider.prototype.valid_request = function(req, callback) {
        if (callback == null) {
            callback = function() {};
        }
        this.parse_request(req);
        if (!this._valid_parameters(req)) {
            return callback(new Error('Invalid LTI parameters'), false);
        }
        return this._valid_oauth(req, function(err, valid) {
            return callback(err, valid);
        });
    };

    Provider.prototype._valid_parameters = function(req) {
        var corrent_message_type, has_resource_link_id;
        corrent_message_type = req.body.lti_message_type === 'basic-lti-launch-request';
        has_resource_link_id = req.body.resource_link_id != null;
        return corrent_message_type && has_resource_link_id;
    };

    Provider.prototype._valid_oauth = function(req, callback) {
        var generated, valid_signature;
        generated = this.signer.build_signature(req, this.consumer_secret);
        valid_signature = generated === req.body.oauth_signature;
        if (!valid_signature) {
            return callback(new Error('Invalid Signature'), false);
        }
        return this.nonceStore.isNew(req.body.oauth_nonce, req.body.oauth_timestamp, function(err, valid) {
            if (!valid) {
                return callback(new Error('Expired nonce'), false);
            } else {
                return callback(null, true);
            }
        });
    };

    Provider.prototype.parse_request = function(req) {
        var key, val, _ref;
        _ref = req.body;
        for (key in _ref) {
            val = _ref[key];
            if (key.match(/^oauth_/)) {
                continue;
            }
            this.body[key] = val;
        }
        this.launch_request = this.body.lti_message_type === 'basic-lti-launch-request';
        this.outcome_service = !!(this.body.lis_outcome_service_url && this.body.lis_result_sourcedid);
        this.userId = this.body.user_id;
        this.roles = this.body.roles;
        this.context_id = this.body.context_id;
        this.context_label = this.body.context_label;
        this.language = this.body.launch_presentation_locale;
        this.firstName = this.body.lis_person_name_given;
        this.lastName = this.body.lis_person_name_family;
        this.fullName = this.body.lis_person_name_full;
        this.email = this.body.lis_person_contact_email_primary;
        return this.context_title = this.body.context_title;
    };

    return Provider;

})();
