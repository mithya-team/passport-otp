"use strict";
const passport = require("passport-strategy");
var speakeasy = require("speakeasy");
var _ = require("lodash");
var validate = require("./lib/util").validate;
var err = () => {
  throw new Error(
    `Override method messageProvider(type,data,token) in your passport.js`
  );
};
var moment = require("moment");
var cryptr = require("crypto");
const Strategy = function(options, verify) {
  if (typeof options == "function") {
    verify = options;
    options = {};
  }
  this.callbackURL = options.callbackPath;
  passport.Strategy.call(this);
  this._verify = verify;
  this._messageProvider = options.messageProvider; // This is custom sms service callback function, if it is not provided then defaut twilioService will be used.
  if (!this._messageProvider) {
    err();
  }
  this._modelName = options.otpModel || "Otp";
  this._sendOtpVia = options.sendOtpVia;
  this._window = options.window || 6;
  this._resendEnabled = options.resendEnabled || true;
  this._resendAfter = options.resendAfter || false;
  this._otpDigits = options.digits;
  this._totpData = {
    encoding: "base32",
    digits: this._otpDigits,
    window: this._window
  };
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
  var phone = [req.body.countryCode, req.body.phone] || false;
  var email = req.body.email || false;
  var data = email || phone;
  var phoneRaw = phone.join("");
  try {
    if (req.body.type) {
      if (req.body.type === "phone") {
        await validate(phone, "phone");
      } else if (req.body.type === "email") {
        await validate(email, "email");
      } else if (req.body.type === "multi") {
        await validate({ phone, email }, "multi");
      } else {
        return req.res.json({
          status: 400,
          message: `INVALID_TYPE`
        });
      }
    } else {
      if (req.body.email) {
        await validate(email, "email");
      } else if (req.body.phone) {
        await validate(phone, "phone");
      } else {
        return req.res.json({
          status: 400,
          message: `INVALID_TYPE`
        });
      }
    }
  } catch (err) {
    return req.res.json({
      status: 400,
      message: err.message
    });
  }

  var multiData = { phone, email };
  try {
    if (!req.body.token) {
      self.sendToken.call(self, req, multiData);
    } else {
      self.submitToken.call(self, req.body.token, req, phone, email);
    }
  } catch (e) {
    console.error(e.message);
    return req.res.json({
      statusCode: 400,
      message: e.message
    });
  }
};

var checkReRequestTime = async function(req, data) {
  let OtpModel = req.app.models[this._modelName];
  let phoneIdentity = { countryCode: data.phone[0], phone: data.phone[1] }; //Check for this
  var result = await OtpModel.findOne({
    where: {
      or: [
        {
          and: [
            { "phoneIdentity.countryCode": phoneIdentity.countryCode },
            { "phoneIdentity.phone": phoneIdentity.phone }
          ]
        },
        { emailIdentity: data.email }
      ]
    },
    order: "id DESC"
  });
  if (!result) return false;
  let lastAttempt = result.attempt.lastAttempt;
  let timeDiff = moment().diff(lastAttempt, "seconds");
  if (timeDiff < this._resendAfter) {
    throw new Error(
      `You can resend OTP after ${this._resendAfter - timeDiff} seconds`
    );
  }
  let secret = result.secret;
  var token = speakeasy.totp(
    _.defaults(
      {
        secret: secret
      },
      this._totpData
    )
  );

  let nAttempts = result.attempt.attempts || 0;
  await result.updateAttribute("attempt", {
    lastAttempt: new Date(),
    attempts: nAttempts + 1
  });

  let res = await sendDataViaProvider.call(this, data, token);
  console.log(
    "\n\nMessage Status : " + res.status + "\nDetails -------------->\n",
    res
  );
  console.log("This is the generated token :", token);
  return {
    statusCode: res.status,
    message: "TOKEN_SENT"
  };
};

Strategy.prototype.sendToken = async function(req, multiData) {
  if (this._resendAfter) {
    try {
      let done = await checkReRequestTime.call(this, req, multiData);
      if (done) {
        return req.res.json(done);
      }
    } catch (err) {
      return req.res.json({
        status: 400,
        message: err.message
      });
    }
  }

  const res = req.res;
  var secret = speakeasy.generateSecret();
  var token = speakeasy.totp(
    _.defaults(
      {
        secret: secret.base32
      },
      this._totpData
    )
  );
  let attemptH;
  try {
    let emailIdentity = multiData.email;
    let phoneIdentity = {
      countryCode: multiData.phone[0],
      phone: multiData.phone[1]
    };
    let OtpModel = req.app.models[this._modelName];
    OtpModel.create({
      phoneIdentity: phoneIdentity,
      emailIdentity: emailIdentity,
      secret: secret.base32,
      attempt: { attemptHash: attemptH }
    });

    var result = await sendDataViaProvider.call(this, multiData, token);

    console.log(
      "\n\nMessage Status : " + result.status + "\nDetails -------------->\n",
      result
    );
    console.log("This is the generated token :", token);
    return res.json({
      statusCode: result.status,
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

var sendDataViaProvider = async function(multiData, token) {
  let result;
  try {
    result = await this._messageProvider(this._sendOtpVia, multiData, token);
    return result;
  } catch (error) {
    throw new Error(error.message);
  }
};

Strategy.prototype.submitToken = async function(token, req, phone, email) {
  const self = this;
  var data = { phone, email };
  var email = email;
  var phone = phone;
  try {
    let result=await self.verifyToken(req, data, token);
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
        result
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

Strategy.prototype.verifyToken = async function(req, data, tokenEnteredByUser) {
  let OtpModel = req.app.models[this._modelName];
  let phoneIdentity = { countryCode: data.phone[0], phone: data.phone[1] };
  var result = await OtpModel.findOne({
    where: {
      or: [
        {
          and: [
            { "phoneIdentity.countryCode": phoneIdentity.countryCode },
            { "phoneIdentity.phone": phoneIdentity.phone }
          ]
        },
        { emailIdentity: data.email }
      ]
    },
    order: "id DESC"
  });
  if (result) console.log(`Identity for ${data} was found.\n${result}`);
  if (!result) {
    throw new Error(`INVALID_DATA`);
  }
  let verifDataOps = _.defaults(
    {
      secret: result.secret,
      token: tokenEnteredByUser
    },
    this._totpData
  );
  var tokenValidates = speakeasy.totp.verify(verifDataOps);

  if (!tokenValidates) {
    throw new Error("Invalid token");
  }
  return result
};

// Expose constructor.
module.exports = Strategy;
