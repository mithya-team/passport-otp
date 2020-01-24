"use strict";
const passport = require("passport-strategy");
var speakeasy = require("speakeasy");
var findcountryCodes = require("./countryCodes");
var _ = require("lodash");

var err=()=>{
  throw new Error(`Override method messageProvider(type,data,token) in your passport.js`);
}
const Strategy = function(options, verify) {
  if (typeof options == "function") {
    verify = options;
    options = {};
  }
  this.callbackURL = options.callbackPath;
  passport.Strategy.call(this);
  this._verify = verify;
  this._messageProvider = options.messageProvider|| err()  // This is custom sms service callback function, if it is not provided then defaut twilioService will be used.
  this._modelName = options.otpModel || "Otp";
  this._sendOtpVia = options.sendOtpVia;
  this._window = options.window || 6;


};

Strategy.prototype.authenticate = async function(req, options) {
  if (!req.app.models[this._modelName]) {
    console.error(
      "Model " +
        this._modelName +
        " doesn't exist.\nPossible Solution --------->\n" +
        "1. Create a model with schema as follow: " +
        'phone(string), secret(string).\n2. Pass the name of model/collection in the authConfig.json file under the "otp" module configuration as follows:\n' +
        '```\n"otpModel":"YOUR MODEL NAME"\n```\n'
    );

    return req.res.json({
      statusCode: 400,
      message: "error occured"
    });
  }

  const self = this;
  var phone;
  this._sendOtpVia = req.body.type;
  var phone = [req.body.countryCode, req.body.mobile] || req.body.phone;
  var email = req.body.email || "";
  var data = email || phone;
  var phoneRaw = phone.join("");

  if (req.body.type === "multi") {
    if (phoneRaw.length == 0 || email.length == 0) {
      return req.res.json({
        statusCode: 400,
        message: "Provide both email and phone"
      });
    }
  }
  var multiData = {
    phone: phoneRaw.length ? phoneRaw : false,
    email: email.length ? email : false
  };
  try {
    if (!req.body.token) {
      await self.validate(data);

      var phone = phoneRaw;
      self.sendToken.call(self, req, multiData);
    } else {
      if (
        Array.isArray(data.phone) ||
        (data.email && data.email.length !== 0)
      ) {
        await self.validate(data);
      }

      self.submitToken.call(self, req.body.token, req, phoneRaw, email);
    }
  } catch (e) {
    console.error(e.message);
    return req.res.json({
      statusCode: 400,
      message: e.message
    });
  }
};

Strategy.prototype.sendToken = async function(req, multiData) {
  const res = req.res;
  var secret = speakeasy.generateSecret();
  var token = speakeasy.totp({
    secret: secret.base32,
    encoding: "base32"
  });

  try {
    for (let data in multiData) {
      let dat = multiData[data];
      if (dat) {
        req.app.models[this._modelName].create({
          identity: dat,
          secret: secret.base32
        });
      }
    }

    var result;
    if (this._messageProvider) {
      result = await this._messageProvider(this._sendOtpVia, multiData, token);
    } else {
      throw new Error(`Override method messageProvider in your authConfig.json`);
      result = await this._messageClient.sendMessage(emailOrPhone, token);
    }

    console.log(
      "\n\nMessage Status : " + result.status + "\nDetails -------------->\n",
      result
    );
    console.log("This is the generated token :", token);
    return res.json({
      statusCode: 202,
      message: "TOKEN_SENT"
    });
  } catch (err) {
    console.log(err);
    return res.json({
      statusCode: 400,
      message: err.message
    });
  }
};

Strategy.prototype.validate = async function(emailOrPhone) {
  if (Array.isArray(emailOrPhone)) {
    var countryCode = emailOrPhone[0];
    var mobile = emailOrPhone[1];
    if (!countryCode || !findcountryCodes(countryCode)) {
      throw new Error("Invalid Country Code");
    }
    var phoneValidation = /^\d{10}$/;
    if (!mobile || !mobile.match(phoneValidation)) {
      throw new Error("Invalid mobile number");
    }
  } else {
    var emailValidation = /^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$/;
    if (!emailOrPhone || !emailOrPhone.match(emailValidation)) {
      throw new Error("Invalid Email");
    }
  }
};

Strategy.prototype.submitToken = async function(token, req, phone, email) {
  const self = this;
  var data = _.defaultTo(email, phone);
  var email = email||req.body.email || "";
  var phone = phone||req.body.phone || "";
  try {
    await self.verifyToken(req, data, token);
    function verified(err, user, info) {
      if (err) {
        return self.error(err);
      }
      if (!user) {
        return self.fail(info);
      }
      self.success(user, info);
    }
    return self._verify(
      req,
      null,
      null,
      {
        phone: phone||email,
        username: email||phone,
        emails: !email
          ? [{ value: phone + "@anonymous.com" }]
          : [{ value: email }],
        id: email||phone
      },
      verified
    );
  } catch (e) {
    console.error(e.message);
    return req.res.json({
      statusCode: 400,
      message: e.message
    });
  }
};

Strategy.prototype.verifyToken = async function(
  req,
  phoneOrEmail,
  tokenEnteredByUser
) {
  var phoneOrEmail = req.body.phone || req.body.email;
  var result = await req.app.models[this._modelName].find({
    where: { identity: phoneOrEmail },
    order: "id DESC",
    limit: 1
  });
  if (result.length == 0) {
    throw new Error(phoneOrEmail + " doesn't exist in our database...");
  }
  var tokenValidates = speakeasy.totp.verify({
    secret: result[0].secret,
    encoding: "base32",
    token: tokenEnteredByUser,
    window: this._window
  });
  if (!tokenValidates) {
    throw new Error("Invalid token");
  }
};

// Expose constructor.
module.exports = Strategy;
