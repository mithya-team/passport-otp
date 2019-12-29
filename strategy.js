'use strict';
const passport = require('passport-strategy');

const Strategy = function (options, verify) {

    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    console.log('Strategy.constructor', options, verify);
    this.callbackURL = options.callbackURL
    passport.Strategy.call(this);
    this.name = 'local';
    this._verify = verify;


}

Strategy.prototype.sendToken = async (req, phone) => {

    const res = req.res;

    // TODO Generate and send token to the phone number.


    return res.json({
        statusCode: 202,
        message: "TOKEN_SENT"
    });
}

Strategy.prototype.authenticate = async function (req, options) {
    const self = this;
    
    let data = Object.assign(req.query, req.body) || {};
    function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }

        self.success(user, info);
    }
    if (!data.phone) {
        return this.error({
            statusCode: 400,
            message: "phone is required"
        });
    }
    if (!data.token) {
        return this.sendToken(req, data.phone);
    }
    else {
        const isValidToken = await this.verifyToken(data.phone, data.token);
        if (!isValidToken) {
            return this.error({
                statusCode: 400,
                message: "INVALID_TOKEN"
            })
        }
        return this._verify(req, null, null, {
            phone: data.phone,
            username: data.phone
        }, verified);
    }

}

Strategy.prototype.verifyToken = async (phone, token) => {
    // TODO Create logic to validate token
    return phone === token;
}


// Expose constructor.
module.exports = Strategy;