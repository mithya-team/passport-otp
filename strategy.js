'use strict';
const passport = require('passport-strategy');
var speakeasy = require('speakeasy')
const OtpSecret = require('./models/OtpSecret')
const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/otpDatabase');
const Strategy = function (options, verify) {

    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    // console.log('Strategy.constructor', options, verify);
    this.callbackURL = options.callbackURL
    passport.Strategy.call(this);
    this.name = 'otp';
    this._verify = verify;
    this._messageProvider = options.messageProvider;
}

Strategy.prototype.sendToken = async (req, phone) => {

    const res = req.res;

    // TODO Generate and send token to the phone number.
    var secret = speakeasy.generateSecret({ length: 20 });
    var token = speakeasy.totp({
        secret: secret.base32,
        encoding: 'base32'
    });

    var secretSave = new OtpSecret({
        phone : phone,
        secret : secret.base64
    });

    console.log('This is the generated token :',token);
    secretSave.save().then(()=>{
        if(!secret.isNew == false){
            return res.json({
                message:'some error occured, please try again'
            });
        }else{
            console.log('**************************************************data saved to the database')
        }
        return res.json({
            statusCode: 202,
            message: "TOKEN_SENT"
        });
    });
    
    // this._messageProvider(phone,token);z

}

Strategy.prototype.authenticate = async function (req, options) {
    const self = this;
    let data = Object.assign(req.query, req.body) || {};
    const phone = data.countryCode + data.mobile;

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
        return this.sendToken(req, phone);
    }
    else {
        const isValidToken = await this.verifyToken(phone, data.token);
        if (!isValidToken) {
            return this.error({
                statusCode: 400,
                message: "INVALID_TOKEN"
            })
        }
        return this._verify(req, null, null, {
            phone: phone,
            username: phone
        }, verified);
    }

}

Strategy.prototype.verifyToken = async (phone, tokenEnteredByUser) => {
    // TODO Create logic to validate token

    OtpSecret.findOneAndDelete({phone:phone}).then((result)=>{
        // console.log(result.phone + '   ' + result.secret);
        var tokenValidates = speakeasy.totp.verify({
                    secret:result.secret.base64,
                    encoding:'base64',
                    token: tokenEnteredByUser,
                    window : 6
                });
        return tokenValidates;
    });
}


// Expose constructor.
module.exports = Strategy;