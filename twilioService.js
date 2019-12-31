var messageProvider = function (phone, token,keys) {

    const accountSid = keys.accountSid;
    const authToken = keys.authToken;
    const client = require('twilio')(accountSid, authToken);
  
    client.messages
      .create({
        body: 'This is your OTP for login: ' + token,
        from: '+12012926522',
        to: phone // phone number actually consists of country code and 10 digit mobile number
      })
      .then(message => console.log('message sid', message.sid));
  }

  module.exports = messageProvider;