class TwilioService {
  constructor(twilioInfo) {
    if (!twilioInfo.mobileNumber || !twilioInfo.accountSid || !twilioInfo.authToken)
      throw new Error(
        '\nPlease provide all the fields of "twilioInfo" in the provider.json file.\n Example --------------------------------->\n'
        + '```\n"twilioInfo": {\n'
        + '"accountSid": "<YOUR_TWILIO_ACCOUNT_SID>",\n'
        + '"authToken": "YOUR_TWILIO_ACCONT_AUTH_TOKEN",\n'
        + '"mobileNumber": "<YOUR TWILIO MOBILE NUMBER>"\n}\n````'
        + '\nYou may visit your twilio account to get all these credentials.\n');

    this._mobileNumber = twilioInfo.mobileNumber;
    this._message = (!twilioInfo.messageBody) ? '' : twilioInfo.messageBody;
    this._client = require('twilio')(twilioInfo.accountSid, twilioInfo.authToken);
  }
  sendMessage = async (phone, token) => {
    let result = await this._client.messages
      .create({
        body: this._message +'. This is your OTP for login: ' + token,
        from: this._mobileNumber,
        to: phone
      })

    return result;
  }
}

module.exports = TwilioService;