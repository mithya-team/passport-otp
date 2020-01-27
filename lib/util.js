var findcountryCodes = require("../countryCodes");

module.exports.validate = async function(emailOrPhone, flag) {
  if (flag === "email") {
    checkEmail(emailOrPhone);
  } else if (flag === "phone") {
    checkCountryAndPhone(emailOrPhone);
  } else if (flag === "multi") {
    try {
      checkEmail(emailOrPhone.email);
      checkCountryAndPhone(emailOrPhone.phone);
    } catch (err) {
      throw err
    }
  } else {
    //Do nothing
  }
  return;
};

var checkCountryAndPhone = emailOrPhone => {
  let error = new Error(`INVALID_PHONE_DATA`);
  if (!emailOrPhone) throw error;
  emailOrPhone.map(item => {
    if (item.length === 0) throw error;
  });

  var countryCode = emailOrPhone[0];
  var mobile = emailOrPhone[1];
  if (!countryCode || !findcountryCodes(countryCode)) {
    throw new Error("INVALID_COUNTRY_CODE");
  }
  console.log("check for phone validation");
  return;
  //Not valid in all cases
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
  if (!emailOrPhone || !emailOrPhone.match(emailValidation)) {
    throw new Error("Invalid Email");
  }
};
