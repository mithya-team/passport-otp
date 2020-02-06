"use strict";
const passport = require("passport-strategy");
var speakeasy = require("speakeasy");
var _ = require("lodash");
var validate = require("./lib/util").validate;
var bcrypt = require("bcrypt");
var err = err => {
  throw new Error(err);
};
var moment = require("moment");
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
    err(`Override method messageProvider(type,data,token) in your passport.js`);
  }
  this._modelName = options.otpModel || "Otp";
  this._sendOtpVia = options.sendOtpVia;
  // this._window = options.window || 6;
  this._resendEnabled = options.resendEnabled || true;
  this._resendAfter = options.resendAfter || false;
  if (!this._resendAfter) {
    err(`Provide resendAfter interval in authConfig.json`);
  }
  this._otpDigits = options.digits;
  this._verificationRequired = options.verificationRequired && true;
  this._totpData = {
    encoding: "base32",
    digits: this._otpDigits,
    window: 30
  };
  this._UserModel = options.UserModel;
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
  req.body.type = req.body.type || this._sendOtpVia; //check if allowed
  this._sendOtpVia = req.body.type || this._sendOtpVia;
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
    }
  } catch (err) {
    return req.res.json({
      status: 400,
      message: err.message
    });
  }

  var multiData = { phone, email };
  var reqPath = req.path.split("/");
  reqPath = reqPath[reqPath.length - 1];

  if (
    !this._verificationRequired &&
    reqPath === "callback" &&
    !req.body.token
  ) {
    var obj = await overrideVerication.call(this, req, multiData);
    if (obj) {
      return req.res.json({
        status: 400,
        message: obj.message || `USER_EXISTS`
      });
    }
    // if (obj&&obj.status === 400) {
    //   return req.res.json(obj);
    // }
    function verified(err, user, info) {
      if (err) {
        return self.error(err);
      }
      if (!user) {
        return self.fail(info);
      }
      self.success(user, info);
    }
    // obj = obj.toJSON();
    if (phone) {
      phone = {
        countryCode: phone[0],
        phone: phone[1]
      };
    }
    return self._verify(
      req,
      null,
      null,
      {
        phone: phone,
        username: multiData.email,
        emails: !multiData.email
          ? [{ value: +"@anonymous.com" }]
          : [{ value: multiData.email }],
        id: multiData.email || multiData.phone.join(""),
        password: req.body.password,
        emailVerified: false,
        phoneVerified: false
      },
      verified
    );
  }

  try {
    if (!req.body.token) {
      await self.sendToken.call(self, req, multiData);
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
var overrideVerication = async function(req, multiData) {
  let self = this;
  let emailIdentity = multiData.email;
  let phoneIdentity = {
    countryCode: multiData.phone[0],
    phone: multiData.phone[1]
  };
  //warning...will always check for inbuilt user model
  let UserModel = this._UserModel;
  if (!UserModel) {
    throw new Error(`SERVER_ERROR`);
  }

  //Using single query bcz different model structure
  // this._sendOtpVia == "multi"
  //   ? queryMulti(phoneIdentity, emailIdentity, multiData)
  //   : querySingle(phoneIdentity, emailIdentity, multiData);

  var exists = await UserModel.findOne({
    where: {
      or: [
        {
          and: [
            { "phone.countryCode": _.get(phoneIdentity, `countryCode`, false) },
            { "phone.phone": _.get(phoneIdentity, `phone`, false) }
          ]
        },
        { email: emailIdentity }
      ]
    },
    order: "id DESC"
  });

  if (!req.body.password) {
    return {
      status: 400,
      message: `PASSWORD_REQUIRED`
    };
  }
  if (exists) {
    return true;
  }
  return exists;
  // let OtpModel = req.app.models[this._modelName];
  // var query =
  //   this._sendOtpVia == "multi"
  //     ? queryMulti(phoneIdentity, emailIdentity, multiData)
  //     : querySingle(phoneIdentity, emailIdentity, multiData);

  // var exists = await OtpModel.findOne(query);
  // //User exists return error
  // if (exists) {
  //   return false
  // }
  // if (!req.body.password) {
  //   return {
  //     status: 400,
  //     message: `PASSWORD_REQUIRED`
  //   };
  // }

  // var obj = await OtpModel.create({
  //   phoneIdentity: phoneIdentity,
  //   emailIdentity: emailIdentity
  //   password:req.body.password
  // });
  return obj;
};
var checkReRequestTime = async function(req, data) {
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
  if (!result) return false;
  //otp instance was created before sending otp
  try {
    let res = await sendDataViaProvider.call(this, data, token);
    if (!result.attempt) {
      if (!result.secret) result.secret = speakeasy.generateSecret();
      result.attempt = {};
      result.attempt.lastAttempt = new Date();
      result.save();
    }
    let lastAttempt = result.attempt.lastAttempt;
    let timeDiff = moment().diff(lastAttempt, "seconds");
    if (timeDiff < this._resendAfter * 60) {
      throw new Error(
        `You can resend OTP after ${this._resendAfter * 60 - timeDiff} seconds`
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

    console.log(
      "\n\nMessage Status : " + res.status + "\nDetails -------------->\n",
      res
    );
    console.log("This is the generated token :", token);
    return {
      statusCode: res.status,
      message: "TOKEN_SENT"
    };
  } catch (error) {
    return {
      statusCode: 400,
      message: error.message
    };
  }
};

Strategy.prototype.sendToken = async function(req, multiData) {
  let emailIdentity = multiData.email;
  let phoneIdentity = {
    countryCode: multiData.phone[0],
    phone: multiData.phone[1]
  };
  var exists = await this._UserModel.findOne({
    where: {
      or: [
        {
          and: [
            { "phone.countryCode": phoneIdentity.countryCode },
            { "phone.phone": phoneIdentity.phone }
          ]
        },
        { email: emailIdentity }
      ]
    },
    order: "id DESC"
  });
  if (!req.body.password && !exists) {
    throw new Error(`PASSWORD_REQUIRED`);
  }
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
  try {
    let emailIdentity = multiData.email;
    let phoneIdentity = {
      countryCode: multiData.phone[0],
      phone: multiData.phone[1]
    };
    let otpObj = {};
    otpObj.secret = secret.base32;
    if (emailIdentity) {
      otpObj.emailIdentity = emailIdentity;
    }
    if (phoneIdentity) {
      otpObj.phoneIdentity = phoneIdentity;
    }
    if (req.body.password) {
      otpObj.password = this._UserModel.hashPassword(req.body.password);
    }
    let OtpModel = req.app.models[this._modelName];
    await OtpModel.create(otpObj);

    var result = await sendDataViaProvider.call(this, multiData, token);

    // console.log(
    //   "\n\nMessage Status : " + result.status + "\nDetails -------------->\n",
    //   result
    // );
    // console.log("This is the generated token :", token);
    console.log(result,token)
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
    if (result.status === 400) {
      throw new Error(`${this._sendOtpVia.toUpperCase()}_PROVIDER_ERROR`);
    }
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
    let result = await self.verifyToken(req, data, token);
    function verified(err, user, info) {
      if (err) {
        return self.error(err);
      }
      if (!user) {
        return self.fail(info);
      }
      if (result.password) {
        user.updateAttribute("password", result.password);
      }
      // todo WARN can verify both
      if (phone && self._sendOtpVia === "phone") {
        user.updateAttribute("phoneVerified", true);
      }
      if (email && self._sendOtpVia === "email") {
        user.updateAttribute("emailVerified", true);
      }
      self.success(user, info);
    }
    result = result.toJSON();
    if (email) {
      result.emailVerified = true;
    }
    if (phone) {
      result.phoneVerified = true;
    }

    return self._verify(
      req,
      null,
      null,
      {
        phone: result.phoneIdentity,
        username: result.emailIdentity,
        emails: !result.emailIdentity
          ? [{ value: phone.join("") + "@anonymous.com" }]
          : [{ value: result.emailIdentity }],
        id: result.emailIdentity || phone.join(""),
        emailVerified: result.emailVerified,
        phoneVerified: result.phoneVerified
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
var querySingle = (phoneIdentity, emailIdentity, data) => {
  return {
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
  };
};
var queryMulti = (phoneIdentity, emailIdentity, data) => {
  return {
    where: {
      and: [
        { "phoneIdentity.countryCode": phoneIdentity.countryCode },
        { "phoneIdentity.phone": phoneIdentity.phone },
        { emailIdentity: data.email }
      ]
    },
    order: "id DESC"
  };
};

Strategy.prototype.verifyToken = async function(req, data, tokenEnteredByUser) {
  let OtpModel = req.app.models[this._modelName];
  let phoneIdentity = { countryCode: data.phone[0], phone: data.phone[1] };
  let emailIdentity = data.email;
  var query =
    this._sendOtpVia == "multi"
      ? queryMulti(phoneIdentity, emailIdentity, data)
      : querySingle(phoneIdentity, emailIdentity, data);
  var result = await OtpModel.findOne(query);
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
  return result;
};

// Expose constructor.
module.exports = Strategy;
//PROBABLE ISSUES
/* 

  UserIdentity verified flags both gets updated

*/
