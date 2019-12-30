'use strict';
const passport = require('passport-strategy');
var speakeasy = require('speakeasy')
const Strategy = function (options, verify) {

    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    this.callbackURL = options.callbackPath
    passport.Strategy.call(this);
    this.name = 'otp';
    this._verify = verify;
    this._messageProvider = options.messageProvider;
    this._modelName = options.modelToSaveGeneratdKeys;
}



Strategy.prototype.sendToken = async function (req, phone) {
    console.log('phone in the sendToken():', phone)
    const res = req.res;

    // TODO Generate and send token to the phone number.
    var secret = speakeasy.generateSecret();
    var token = speakeasy.totp({
        secret: secret.base32,
        encoding: 'base32'
    });

    console.log(req.app.models['otpSecret']);
    var modelName = this._modelName;
    req.app.models[modelName].create({ phone: phone, secret: secret.base32 }).then((obj) => {
        console.log(obj);
    });
    console.log('This is the generated token :', token);

    return res.json({
        statusCode: 202,
        message: "TOKEN_SENT"
    });
}

Strategy.prototype.authenticate = async function (req, options) {
    const self = this;
    let data = Object.assign(req.query, req.body) || {};
    var phone = data.countryCode + data.mobile;
    console.log('this is the query paramas: ', req.query)
    // const phone = req.body.countryCode + req.body.mobile;
    console.log('PHONE IN THE AUTHENTICATION FUNCTION :', phone);
    function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }

        self.success(user, info);
    }
    if (!phone) {
        return this.error({
            statusCode: 400,
            message: "enter country code and mobile number"
        });
    }
    if (!data.token) {
        return self.sendToken.call(self, req, phone);
    }
    else {
        const isValidToken = await this.verifyToken(req, phone, data.token);

        if (isValidToken == 1) {
            return this.error({
                statusCode: 400,
                message: "This mobile number doesn't exist in our database."
            })
        }
        if (!isValidToken) {
            return this.error({
                statusCode: 400,
                message: "INVALID_TOKEN"
            })
        }
        return this._verify(req, null, null, {
            phone: phone,
            username: phone,
            emails: phone + '@anonymous.com',
            id: phone
        }, verified);
    }

}

Strategy.prototype.verifyToken = async function (req, phone, tokenEnteredByUser) {
    // TODO Create logic to validate token
    console.log(phone);
    var result = await req.app.models[this._modelName].find({ where: { phone: phone }, order: 'id DESC', limit: 1 })
    if (result.length == 0) {
        return 1;
    }
    var tokenValidates = speakeasy.totp.verify({
        secret: result[0].secret,
        encoding: 'base32',
        token: tokenEnteredByUser,
        window: 6
    });
    console.log(result[0].secret, tokenValidates);
    return tokenValidates;
}

// Expose constructor.
module.exports = Strategy;