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
    this._messageProvider = options.messageProvider; // This is custom sms service callback function, if it is not provided then defaut twilioService will be used.
    this._modelName = options.modelToSaveGeneratedKeys;
    this._sendOtpVia = options.sendOtpVia;
    this._twilioInfo = options.twilioInfo;
    this._emailInfo = options.emailInfo;
}

Strategy.prototype.sendToken = async function (req, emailOrPhone) {
    const res = req.res;
    var secret = speakeasy.generateSecret();
    var token = speakeasy.totp({
        secret: secret.base32,
        encoding: 'base32'
    });


    try {

        req.app.models[this._modelName].create({ phone: emailOrPhone, secret: secret.base32 });
        let result = this._sendOtpVia == 'email' ?
            await sendEmail(this._emailInfo, emailOrPhone, token) :
            (!this._messageProvider ? await twilioService(emailOrPhone, token, this._twilioInfo) : await this._messageProvider(emailOrPhone, token));

        console.log(result);
        console.log('This is the generated token :', token);
        return res.json({
            statusCode: 202,
            message: "TOKEN_SENT"
        });

    } catch (err) {
        if (!req.app.models[this._modelName]) {
            console.log(this._modelName + ' doesn\'t exist. create it first in your application, then access it...')
        } else {
            console.log(err);
            return res.json({
                statusCode: 400,
                message: "error occured"
            });
        }
    }
}

Strategy.prototype.authenticate = async function (req, options) {
    const self = this;
    var email, phone;
    let data = Object.assign(req.query, req.body) || {};
    function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }

        self.success(user, info);
    }

    if (this._sendOtpVia == 'phone') {
        var countryCode = data.countryCode;
        var mobile = data.mobile;
        // Country code validation
        if (!countryCode || !findcountryCodes(countryCode)) {
            return this.error({
                statusCode: 400,
                message: 'Invalid country code'
            });
        }
        // mobile number validation
        var phoneValidation = /^\d{10}$/;
        if (!mobile || !mobile.match(phoneValidation)) {
            return this.error({
                statusCode: 400,
                message: 'Invalid mobile number'
            });
        }
        phone = countryCode + mobile;

    } else {
        email = data.email;
        // email vaildation

        var emailValidation = /^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$/;
        if (!email || !email.match(emailValidation)) {
            return this.error({
                statusCode: 400,
                message: 'Invalid email'
            });
        }

    }

    if (!data.token) {
        return self.sendToken.call(
            self,
            req,
            this._sendOtpVia == 'phone' ? phone : email
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
    try {
        var result = await req.app.models[this._modelName].find({ where: { phone: phoneOrEmail }, order: 'id DESC', limit: 1 })
        if (result.length == 0) {
            return 1;
        }
    } catch (err) {
        console.log(err);
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