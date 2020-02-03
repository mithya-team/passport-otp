"use strict";
const passport = require("passport-strategy");
var speakeasy = require("speakeasy");
var _ = require("lodash");
var validate = require("./lib/util").validate;
var bcrypt = require("bcrypt");
var moment = require("moment");
var err = err => {
  throw new Error(err);
};

//Strategy Constructor
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
  this.entryFlow = options.entryFlow || false;
  this.phoneVerReq = _.get(this.entryFlow, `phoneVerificationRequired`, false);
  this.emailVerReq = _.get(this.entryFlow, `emailVerificationRequired`, false);
  if (this.entryFlow) {
    this.entryFlow = true;
  }
  this.passOptions = options.passOptions || false;
  // this._window = options.window || 6;
  this._resendEnabled = options.resendEnabled || true;
  this._resendAfter = options.resendAfter || false;
  if (!this._resendAfter) {
    err(`Provide resendAfter interval in authConfig.json`);
  }
  this._otpDigits = options.digits;
  this.method = options.method || "multiOr";

  this._verificationRequired = options.verificationRequired && true;
  this._totpData = {
    encoding: "base32",
    digits: this._otpDigits
  };
  this._UserModel = options.UserModel;
  this.redirectEnabled = options.redirectEnabled || false;
  this.strictOtp = options.strictOtp;
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

  //Request must contain body
  try {
    if (!req.body) {
      return req.res.json({
        status: 400,
        message: `DATA_NOT_FOUND`
      });
    }

    const self = this;
    let entryFlow = this.entryFlow;
    let email = req.body.email || false;
    let phone = req.body.phone || false;
    let res = req.res;
    let method = this.method;
    let flow = req.body.flow;
    let Otp = req.app.models[this._modelName];
    let User = this._UserModel;
    let data = {};
    if (email) {
      await validate(email, "email");
      data.email = email;
    }

    if (phone) {
      if (!phone.countryCode || !phone.phone) {
        return res.json({
          status: 400,
          message: `INVALID_PHONE_DATA`
        });
      }
      await validate([phone.countryCode, phone.phone], "phone");
      data.phone = phone;
    } else {
      if (!email) err(`PROVIDE_EMAIL_OR_PHONE`);
      phone = { countryCode: false, phone: false };
      data.phone = phone;
    }
    let type;

    if (data.phone && data.phone.countryCode) {
      type = "phone";
    }
    if (data.email) {
      type = "email";
    }
    if (data.phone && data.phone.countryCode && data.email) {
      type = "multi";
    }
    if (req.body.userIns) {
      //this is an authenticated request
      let userIns = req.body.userIns;
      if (!data.email) {
        email = userIns.email;
        data.email = userIns.email;
      }
      if (!data.phone && !data.phone.phone) {
        phone = userIns.phone;
        data.phone = userIns.phone;
      }
      if (!data.email && !data.phone) {
        return req.res.json({
          status: 500,
          message: `INVALID_AUTH_REQUEST`
        });
      }
    }
    if (req.body.token) {
      return await self.submitToken.call(self, req, data, req.body.token, type);
    }
    // if (!req.body.sendToken) {
    //   if (this.phoneVerReq && !phone.countryCode) {
    //     err(`PHONE_REQUIRED`);
    //   }
    //   if (this.emailVerReq && !email) {
    //     err(`EMAIL_REQUIRED`);
    //   }
    // }

    // let user =  await getUser.call(this, data, req);

    let { secret, token } = createNewToken(this._totpData);
    if (type === "multi" && this.strictOtp) {
      token = { email: token };
      token.phone = createNewToken(this._totpData, secret);
    }
    let userIns;

    let query = getQuery("or", email, phone);
    console.log(query);
    let otpObj = { ...data, secret };
    if (req.body.password) {
      await validate(
        { options: this.passOptions, pass: req.body.password },
        "pass"
      );
      otpObj.password = User.hashPassword(req.body.password);
    }
    await checkReRequestTime.call(this, req, data);
    let otp = await Otp.findOrCreate(query, otpObj);
    if (otp[1] === false) {
      secret = otp[0].secret;
      token = createNewToken(this._totpData, secret);
      let updatedIns = await Otp.upsertWithWhere(query, otpObj);
    }
    console.log(token);
    let result = await sendDataViaProvider.call(this, data, token);
    console.log(result);
    return req.res.json({
      statusCode: result.status,
      message: "TOKEN_SENT"
    });
  } catch (error) {
    // console.log(error);
    return req.res.json({
      status: 400,
      message: error.message
    });
  }
};

var checkReRequestTime = async function(req, data) {
  let Otp = req.app.models[this._modelName];
  var result = await Otp.findOne(getQuery("or", data.email, data.phone));
  if (!result) return true;
  let lastAttempt = _.get(result, `attempt.lastAttempt`, false);
  if (!lastAttempt) {
    _.set(result, `attempt.lastAttempt`, new Date());
    result.save();
    return true;
  }
  let timeDiff = moment().diff(lastAttempt, "seconds");
  if (timeDiff < this._resendAfter * 60) {
    err(
      `You can resend OTP after ${this._resendAfter * 60 - timeDiff} seconds`
    );
  }
  let nAttempts = _.get(result, `attempt.attempts`, 0);
  await result.updateAttribute("attempt", {
    lastAttempt: new Date(),
    attempts: nAttempts + 1
  });
  return true;
};
var createNewToken = function(totpData, secret) {
  let old = secret && true;
  secret = secret || speakeasy.generateSecret().base32;
  let token = speakeasy.totp(
    _.defaults(
      {
        secret: secret
      },
      totpData
    )
  );
  if (old) {
    return token;
  }
  return { secret, token };
};

var sendDataViaProvider = async function(data, token) {
  let type, phone;
  if (data.phone && data.phone.countryCode) {
    type = "phone";
    phone = [data.phone.countryCode, data.phone.phone].join("");
  }
  if (data.email) {
    type = "email";
  }
  if (data.phone && data.phone.countryCode && data.email) {
    type = "multi";
  }
  let result = await this._messageProvider(type, { ...data, phone }, token);
  if (result.status === 400) {
    err(`${type.toUpperCase()}_PROVIDER_ERROR`);
  }
  return result;
};
var getUser = async function(data, req) {
  let email = data.email || false;
  let countryCode = data.phone.countryCode || false;
  let phone = data.phone || false;
  let query = getQuery("or", email, phone);
  let UserModel = this._UserModel;
  let user = await UserModel.findOne(query);
  if (!user) {
    return false;
  }
  return user;
};

var getQuery = function(type, email = false, phone = false) {
  let countryCode = false;

  if (phone && phone.countryCode) {
    countryCode = phone.countryCode;
    phone = phone.phone;
  } else {
    phone = false;
  }
  let orArr = [];
  let andArr = [];
  if (phone && countryCode) {
    orArr.push({
      and: [{ "phone.countryCode": countryCode }, { "phone.phone": phone }]
    });
    andArr.push({ "phone.countryCode": countryCode }, { "phone.phone": phone });
  }
  if (email) {
    orArr.push({ email: email });
    andArr.push({ email: email });
  }
  let queryOr = {
    where: {
      or: orArr
    },
    order: "id DESC"
  };
  let queryAnd = {
    where: {
      and: andArr
    },
    order: "id DESC"
  };

  if (type === "and") {
    return queryAnd;
  }
  return queryOr;
};

var defaultCallback = (self, type, email, phone, result, redirect) => async (
  err,
  user,
  info
) => {
  if (err && typeof redirect !== "function") {
    return self.error(err);
  }
  if (!user && typeof redirect !== "function") {
    return self.fail(info);
  }
  if (result.password) {
    await user.updateAttribute("password", result.password);
    await user.updateAttribute("passwordSetup", true);
  }
  // todo WARN can verify both
  if (phone && phone.countryCode && email) {
    user.updateAttribute("phoneVerified", true);
    user.updateAttribute("emailVerified", true);
  } else {
    if (phone && phone.countryCode && type === "phone") {
      user.updateAttribute("phoneVerified", true);
    }
    if (email && type === "email") {
      user.updateAttribute("emailVerified", true);
    }
  }
  result.userId = user.id;
  result.save();

  if (typeof redirect === "function") {
    redirect(err, user, info);
  } else {
    self.success(user, info);
  }
};

var createProfile = result => {
  let obj = {};
  if (result.email) {
    obj.email = result.email;
    obj.username = obj.email;
    obj.emails = [
      {
        value: obj.email
      }
    ];
    obj.id = obj.email;
  }
  if (result.phone && result.phone.countryCode) {
    obj.phone = result.phone;
    let ph = [result.phone.countryCode, result.phone.phone].join("");
    if (!obj.username) {
      obj.username = ph;
    }
    if (!obj.emails) {
      obj.emails = [
        {
          value: ph + `@passport-otp.com`
        }
      ];
    }
    if (!obj.id) {
      obj.id = ph;
    }
  }
  return obj;
};

Strategy.prototype.submitToken = async function(req, data, token, type) {
  const self = this;
  let email = data.email || false;
  let phone = data.phone || false;
  let result = await self.verifyToken(req, data, token, type);
  // result = result.toJSON();
  result.emailVerified = email && true;
  result.phoneVerified = phone && true;
  var profile = createProfile(result.toJSON());
  let redirect = this.redirectEnabled || false;
  if (!redirect) {
    redirect = function(err, user, info) {
      if (err) return req.res.json({ err });
      return req.res.json({
        status: 200,
        ...user.toJSON(),
        accessToken: info.accessToken
      });
    };
  }
  return self._verify(
    req,
    null,
    null,
    profile,
    defaultCallback(self, type, email, phone, result, redirect)
  );
};

Strategy.prototype.verifyToken = async function(
  req,
  data,
  tokenEnteredByUser,
  type
) {
  let Otp = req.app.models[this._modelName];
  let query;
  if (type === "multi") {
    query = getQuery("and", data.email, data.phone);
  } else {
    query = getQuery("or", data.email, data.phone);
  }
  let result = await Otp.findOne(query);
  if (!result) {
    err(`INVALID_DATA`);
  }
  if (result) {
    console.log(`IDENTITY_FOUND \n${data}\n${result}`);
  }

  let verifDataOps = _.defaults(
    {
      secret: result.secret,
      token: tokenEnteredByUser
    },
    this._totpData
  );
  let tokenValidates = speakeasy.totp.verify(verifDataOps);
  if (!tokenValidates) {
    err(`INVALID_TOKEN`);
  }
  return result;
};

module.exports = Strategy;
