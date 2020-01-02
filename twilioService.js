var messageProvider = async function (phone, token, twilioInfo) {

  const accountSid = twilioInfo[0].accountSid;
  const authToken = twilioInfo[1].authToken;
  const mobileNumber = twilioInfo[2].mobileNumber;
  const client = require('twilio')(accountSid, authToken);



  let result = await client.messages
    .create({
      body: 'This is your OTP for login: ' + token,
      from: mobileNumber,
      to: phone // phone number actually consists of country code and 10 digit mobile number
    });

  return result;


}
module.exports = messageProvider;