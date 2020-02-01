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
  this._sendOtpVia = options.sendOtpVia;
  this.entryFlow = options.entryFlow || false;
  this.phoneVerReq = _.get(this.entryFlow, `phoneVerificationRequired`, false);
  this.emailVerReq = _.get(this.entryFlow, `emailVerificationRequired`, false);
  if (this.entryFlow) {
    this.entryFlow = true;
  }
  // this._window = options.window || 6;
  this._resendEnabled = options.resendEnabled || true;
  this._resendAfter = options.resendAfter || false;
  if (!this._resendAfter) {
    err(`Provide resendAfter interval in authConfig.json`);
  }
  this._otpDigits = options.digits;
  this.method = options.method || "multiOr";
  // if (this.method !== "multiOr" || this.method !== "multiAnd") {
  //   err(`INVALID_METHOD_TYPE`);
  // }
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

  //Request must contain body
  try {
    if (!req.body) {
      return req.res.json({
        status: 400,
        message: `DATA_NOT_FOUND`
      });
    }
    if (req.body.flow !== "login" && req.body.flow !== "signup") {
      err(`INVALID_OTP_FLOW`);
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

    if (
      flow === "login" &&
      _.includes(this.phoneVerReq, "login") &&
      !phone.countryCode
    ) {
      err(`PHONE_REQUIRED`);
    }
    if (
      flow === "signup" &&
      _.includes(this.phoneVerReq, "signup") &&
      !phone.countryCode
    ) {
      err(`PHONE_REQUIRED`);
    }
    if (flow === "login" && _.includes(this.emailVerReq, "login") && !email) {
      err(`EMAIL_REQUIRED`);
    }
    if (flow === "signup" && _.includes(this.emailVerReq, "signup") && !email) {
      err(`EMAIL_REQUIRED`);
    }
    // if (method === "multiOr") {
    //   if (!email || !phone) {
    //     err(`PHONE_OR_EMAIL_REQUIRED`);
    //   }
    // }
    // if (method === "multiAnd") {
    //   if (!email && !phone) {
    //     err(`PHONE_AND_EMAIL_REQUIRED`);
    //   }
    // }
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
    if (req.body.token) {
      return await self.submitToken.call(self, req, data, req.body.token, type);
    }
    if (!req.body.password && flow === "signup") {
      return res.json({
        status: 400,
        message: "PASSWORD_REQUIRED"
      });
    }

    let user = await getUser.call(this, data, req);
    if (user && flow === "signup") {
      err(`USER_EXISTS`);
    }
    let { secret, token } = createNewToken(this._totpData);
    await checkReRequestTime.call(this, req, data);
    if (flow === "signup") {
      //create a otp instance
      let password = User.hashPassword(req.body.password);
      let query = getQuery("or", email, phone);
      let otpData = { ...data };
      if (!otpData.phone.countryCode) {
        delete otpData["phone"];
      }
      let otp = await Otp.findOrCreate(
        { query },
        {
          ...otpData,
          password,
          secret
        }
      );
      // let otpInstance = await Otp.create({ ...data, password, secret });
      let result = await sendDataViaProvider.call(this, data, token);
      console.log(result, token);
      return req.res.json({
        statusCode: result.status,
        message: "TOKEN_SENT"
      });
    }
    if (flow === "login") {
      let query = getQuery("or", email, phone);
      let otp = await Otp.findOrCreate(
        { query },
        {
          ...data,
          secret
        }
      );
      let result = await sendDataViaProvider.call(this, data, token);
      console.log(result, token);
      return req.res.json({
        statusCode: result.status,
        message: "TOKEN_SENT"
      });
    }
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
var createNewToken = function(totpData) {
  let secret = speakeasy.generateSecret().base32;
  let token = speakeasy.totp(
    _.defaults(
      {
        secret: secret
      },
      totpData
    )
  );
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

  // console.log(result, token);
  // return req.res.json({
  //   statusCode: result.status,
  //   message: "TOKEN_SENT"
  // });
  // try {
  //   result = await this._messageProvider(this._sendOtpVia, multiData, token);
  //   if (result.status === 400) {
  //     throw new Error(`${this._sendOtpVia.toUpperCase()}_PROVIDER_ERROR`);
  //   }
  //   return result;
  // } catch (error) {
  //   throw new Error(error.message);
  // }
};
var getUser = async function(data, req) {
  // if (!this._verificationRequired) return;
  let email = data.email || false;
  let countryCode = data.phone.countryCode || false;
  let phone = data.phone.phone || false;
  let query = getQuery("or", email, phone);
  let UserModel = this._UserModel;
  let user = await UserModel.findOne(query);
  if (!user) {
    return false;
  }
  return user;
  // let phoneVerReq = this.phoneVerReq,
  //   emailVerReq = this.emailVerReq;

  // if (phoneVerReq && !user.phoneVerified) {
  //   return false;
  // }
  // if (emailVerReq && !user.emailVerified) {
  //   return false;
  // }
  // let data = {};
  // data.user = user;
  // return data;
  ////////////////////////////////////////
  // if (phoneVerReq && user.phoneVerified) {
  //   return false;
  // }
  // if (!emailVerReq && !user.emailVerified) {
  //   return false;
  // }
  // return false;
  ////////////////////////////////////////
};

var getQuery = function(type, email = false, phone = false) {
  let countryCode = false;

  if (phone && phone.countryCode) {
    countryCode = phone.countryCode;
    phone = phone.phone;
  } else {
    phone = false;
  }
  let queryOr = {
    where: {
      or: [
        {
          and: [{ "phone.countryCode": countryCode }, { "phone.phone": phone }]
        },
        { email: email }
      ]
    },
    order: "id DESC"
  };
  let queryAnd = {
    where: {
      and: [
        { "phone.countryCode": countryCode },
        { "phone.phone": phone },
        { email: email }
      ]
    },
    order: "id DESC"
  };

  if (type === "and") {
    return queryAnd;
  }
  return queryOr;
};

var defaultCallback = (self, type, email, phone, result) => (
  err,
  user,
  info
) => {
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

  self.success(user, info);
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
  // return {
  //   phone: result.phone,
  //   username: result.email,
  //   emails: !result.phone
  //     ? [
  //         {
  //           value: [phone.countryCode, phone.phone].join("") + "@anonymous.com"
  //         }
  //       ]
  //     : [{ value: result.emailIdentity }],
  //   id: result.emailIdentity || phone.join(""),
  //   emailVerified: result.emailVerified,
  //   phoneVerified: result.phoneVerified
  // };
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
  return self._verify(
    req,
    null,
    null,
    profile,
    defaultCallback(self, type, email, phone, result)
  );

  try {
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
  // let phoneIdentity = { countryCode: data.phone[0], phone: data.phone[1] };
  // let emailIdentity = data.email;
  // var query =
  //   this._sendOtpVia == "multi"
  //     ? queryMulti(phoneIdentity, emailIdentity, data)
  //     : querySingle(phoneIdentity, emailIdentity, data);
  // var result = await OtpModel.findOne(query);
  // if (result) console.log(`Identity for ${data} was found.\n${result}`);
  // if (!result) {
  //   throw new Error(`INVALID_DATA`);
  // }
  // let verifDataOps = _.defaults(
  //   {
  //     secret: result.secret,
  //     token: tokenEnteredByUser
  //   },
  //   this._totpData
  // );
  // var tokenValidates = speakeasy.totp.verify(verifDataOps);

  // if (!tokenValidates) {
  //   throw new Error("Invalid token");
  // }
  // return result;
};

//  Strategy.prototype.sendToken = async function(req, multiData) {
//   let emailIdentity = multiData.email;
//   let phoneIdentity = {
//     countryCode: multiData.phone[0],
//     phone: multiData.phone[1]
//   };
//   var exists = await this._UserModel.findOne({
//     where: {
//       or: [
//         {
//           and: [
//             { "phone.countryCode": phoneIdentity.countryCode },
//             { "phone.phone": phoneIdentity.phone }
//           ]
//         },
//         { email: emailIdentity }
//       ]
//     },
//     order: "id DESC"
//   });
//   if (!req.body.password && !exists) {
//     throw new Error(`PASSWORD_REQUIRED`);
//   }
//   if (this._resendAfter) {
//     try {
//       let done = await checkReRequestTime.call(this, req, multiData);
//       if (done) {
//         return req.res.json(done);
//       }
//     } catch (err) {
//       return req.res.json({
//         status: 400,
//         message: err.message
//       });
//     }
//   }

//   const res = req.res;
//   var secret = speakeasy.generateSecret();
//   var token = speakeasy.totp(
//     _.defaults(
//       {
//         secret: secret.base32
//       },
//       this._totpData
//     )
//   );
//   try {
//     let emailIdentity = multiData.email;
//     let phoneIdentity = {
//       countryCode: multiData.phone[0],
//       phone: multiData.phone[1]
//     };
//     let otpObj = {};
//     otpObj.secret = secret.base32;
//     if (emailIdentity) {
//       otpObj.emailIdentity = emailIdentity;
//     }
//     if (phoneIdentity) {
//       otpObj.phoneIdentity = phoneIdentity;
//     }
//     if (req.body.password) {
//       otpObj.password = this._UserModel.hashPassword(req.body.password);
//     }
//     let OtpModel = req.app.models[this._modelName];
//     await OtpModel.create(otpObj);

//     var result = await sendDataViaProvider.call(this, multiData, token);

//     // console.log(
//     //   "\n\nMessage Status : " + result.status + "\nDetails -------------->\n",
//     //   result
//     // );
//     // console.log("This is the generated token :", token);
//     console.log(result, token);
//     return res.json({
//       statusCode: result.status,
//       message: "TOKEN_SENT"
//     });
//   } catch (err) {
//     console.log(err);
//     return res.json({
//       statusCode: 400,
//       message: err.message
//     });
//   }
// };

module.exports = Strategy;
