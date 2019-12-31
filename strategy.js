'use strict';
const passport = require('passport-strategy');
var speakeasy = require('speakeasy')
var findcountryCodes = require('./countryCodes');
var sendEmail = require('./sendEmail');
var twilioService = require('./twilioService');
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
    this._modelName = options.modelToSaveGeneratedKeys;
    this._sendOtpVia = options.sendOtpVia;
    this._email = options.userInfoForEmail[0].gmail;
    this._password = options.userInfoForEmail[1].password;
    this._keys = options.twilioKeys;
}



Strategy.prototype.sendToken = async function (req, emailOrPhone) {
    const res = req.res;
    var secret = speakeasy.generateSecret();
    var token = speakeasy.totp({
        secret: secret.base32,
        encoding: 'base32'
    });

    await req.app.models[this._modelName].create({ phone: emailOrPhone, secret: secret.base32 }); // add a check to know whether data saved to database or some error occured, see async docs for more inof...

    this._sendOtpVia == 'email' ?
        sendEmail(this._email, this._password, emailOrPhone, token) :
        (!this._messageProvider ? twilioService(emailOrPhone,token,this._keys) : this._messageProvider(emailOrPhone, token));

    console.log('This is the generated token :', token);
    return res.json({
        statusCode: 202,
        message: "TOKEN_SENT"
    });
}

Strategy.prototype.authenticate = async function (req, options) {
    const self = this;
    var email, phone;
    let data = Object.assign(req.query, req.body) || {};
    if (this._messageProvider == 'phone') {
        var countryCode = data.countryCode;
        var mobile = data.mobile;
        // Country code validation
        if (!findcountryCodes(countryCode)) {
            return this.error({
                statusCode: 400,
                message: 'Invalid country code'
            });
        }
        // mobile number validation
        var phoneValidation = /^\d{10}$/;
        if (!mobile.match(phoneValidation)) {
            return this.error({
                statusCode: 400,
                message: 'Invalid mobile number'
            });
        }
        phone = countryCode + mobile;

    } else {
        email = data.email;
        // email vaildation
        if (email) {
            var emailValidation = /^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$/;
            if (!email.match(emailValidation)) {
                return this.error({
                    statusCode: 400,
                    message: 'Invalid email'
                });
            }
        }
    }

    function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }

        self.success(user, info);
    }

    if (!data.token) {
        return self.sendToken.call(
            self,
            req,
            this._messageProvider == 'phone' ? phone : email
        );
    }
    else {
        const isValidToken = await this.verifyToken(
            req,
            this._sendOtpVia == 'email' ? email : phone,
            data.token
        );

        if (isValidToken == 2) {
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
            emails: !email ? [{ 'value': phone + '@anonymous.com' }] : [{ 'value': email }],
            id: phone,
        }, verified);
    }

}

Strategy.prototype.verifyToken = async function (req, phoneOrEmail, tokenEnteredByUser) {
    var result = await req.app.models[this._modelName].find({ where: { phone: phoneOrEmail }, order: 'id DESC', limit: 1 })
    if (result.length == 0) {
        return 1;
    }
    var tokenValidates = speakeasy.totp.verify({
        secret: result[0].secret,
        encoding: 'base32',
        token: tokenEnteredByUser,
        window: 6
    });
    return tokenValidates;
}

// Expose constructor.
module.exports = Strategy;