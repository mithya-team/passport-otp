var messageProvider = function (phone, token,twilioInfo) {

  const accountSid = twilioInfo[0].accountSid;
  const authToken = twilioInfo[1].authToken;
  const mobileNumber = twilioInfo[2].mobileNumber;
  const client = require('twilio')(accountSid, authToken);

  client.messages
    .create({
      body: 'This is your OTP for login: ' + token,
      from: mobileNumber,
      to: phone // phone number actually consists of country code and 10 digit mobile number
    })
    .then(message => console.log('message sid', message.sid));
}

module.exports = messageProvider;