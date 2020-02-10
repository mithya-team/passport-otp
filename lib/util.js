var findcountryCodes = require("../countryCodes");
var _ = require("lodash");
module.exports.validate = async function (emailOrPhone, flag) {
  if (flag === "email") {
    return checkEmail(emailOrPhone);
  } else if (flag === "phone") {
    return checkCountryAndPhone(emailOrPhone);
  } else if (flag === "multi") {
    try {
      return checkCountryAndPhone(emailOrPhone.phone) && checkEmail(emailOrPhone.email);
    } catch (err) {
      throw err;
    }
  } else if (flag === "pass") {
    return checkPassword(emailOrPhone.options, emailOrPhone.pass);
  } else {
    //Do nothing
  }
  return;
};

var checkCountryAndPhone = emailOrPhone => {
  let error = new Error(`INVALID_PHONE_DATA`);
  if (!emailOrPhone) throw error;
  emailOrPhone.map(item => {
    if (item && item.length === 0) throw error;
  });

  var countryCode = emailOrPhone[0];
  var mobile = emailOrPhone[1];
  if (!countryCode || !findcountryCodes(countryCode)) {
    throw new Error("INVALID_COUNTRY_CODE");
  }
  console.log("check for phone validation");
  // return;
  //Check 10 digit validation
  var phoneValidation = /^\d{10}$/;
  if (!mobile || !mobile.match(phoneValidation)) {
    throw new Error("INVALID_PHONE_NUMBER");
  }
};

var checkEmail = emailOrPhone => {
  let error = new Error(`INVALID_EMAIL_DATA`);
  if (!emailOrPhone) throw error;
  if (emailOrPhone.length === 0) throw error;
  var emailValidation = /^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$/;
  if(_.isObject(emailOrPhone)){
    return false
  }
  if (!emailOrPhone && !emailOrPhone.match(emailValidation)) {
    throw new Error("Invalid Email");
  }
};

var checkPassword = function (options, password) {
  var passConfig = options;
  if (!passConfig) return;
  let minLen = passConfig.minLen || 6;
  let digitRequired = passConfig.digitRequired;
  let lowerCase = passConfig.lowerCase;
  let upperCase = passConfig.upperCase;
  let specialChar = passConfig.specialChar;
  //bug....
  // min len by default 6
  if (password.length < minLen) {
    throw new Error(`PASSWORD_LEN_LESS_THAN_${minLen}`);
  }
  let alphaReg = `^(?=.*[A-Za-z])[A-Za-z\\d@$!%*?&]{${minLen},}$`;
  if (!password.match(alphaReg)) {
    throw new Error(`PASSWORD_ALPHABET_REQUIRED`);
  }
  let digitReg = `^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d@$!%*?&]{${minLen},}$`;
  if (digitRequired && !password.match(digitReg)) {
    throw new Error(`PASSWORD_DIGIT_REQUIRED`);
  }
  let specialCharReg = `^(?=.*[A-Za-z])(?=.*[@$!%*#?&])(?=.*\\d)[A-Za-z\\d@$!%*?&]{${minLen},}$`;
  if (specialChar && !password.match(specialCharReg)) {
    throw new Error(`PASSWORD_SPECIAL_CHAR_REQUIRED`);
  }
  let upperCaseReg = `^(?=.*[A-Z])(?=.*[A-Za-z])[A-Za-z\\d@$!%*?&]{${minLen},}$`;
  if (upperCase && !password.match(upperCaseReg)) {
    throw new Error(`PASSWORD_UPPER_CASE_REQUIRED`);
  }
  // let lowerCaseReg = `^(?=.*[a-z])(?=.*[A-Z])[A-Za-z\\d@$!%*?&]{${minLen},}$`;
  // if (lowerCase && !password.match(lowerCaseReg)) {
  //   throw new Error(`PASSWORD_LOWER_CASE_REQUIRED`);
  // }
};
