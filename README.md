# passport-otp

- [Passport](http://passportjs.org/) strategy for authenticating user using OTP (one time password).
- Currently, this module can be used only in loopback application but we wish to extend it's usage in all Node.js applications
- You can send OTP to user using email(Gmail by default) or SMS service (Twilio by default). You may override default services of email and SMS by defining your custom method in your loopback application.

## Install

    $ npm install git+https://github.com/yash17525/passport-otp.git

## Usage

#### Provide configuation in the configuartion file of your loopback-application.

```
"otp": {
    "authScheme": "otp",
    "provider": "passport-otp",
    "module": "passport-otp",
    "authPath": "/auth/otp",
    "callbackPath": "/auth/verify",
    "successRedirect": "/auth/account",
    "failureRedirect": "/otp",
    "failureFlash": true,
    "callbackHTTPMethod": "post",
    "modelToSaveGeneratedKeys": "YOUR_MODEL_NAME (schema for model is : identity(string),secret(string) )",
    "sendOtpVia": "choose one of "phone" or "email"",
    "emailInfo": {
      "gmail": "YOUR_GMAIL_ID",
      "password": "GMAIL_PASSWORD",
      "emailSubject": "OTP for login to <YOUR_APPLICATION_NAME>"
    },
    "twilioInfo": {
      "accountSid": "TWILIO_ACCOUNT_SID",
      "authToken":"TWILIO_ACCOUNT_AUTH_TOKEN",
      "mobileNumber": "TWILIO_ACCOUNT_MOBILE_NUMBER"
    }
  }
```

- "authPath" is the endpoint where you will have to make GET request with mobile number, country code or with email-id.
- "callbackPath" is the endpoint where you will have to make a POST request with OTP,mobile number,country code or with OTP,email-id.
- "modelToSaveGenerateKeys" is the model where the passport-otp module will save generated token secret. This model will have schema as , identity(string),secret(string). "secret" field will be used to save the generated secret and identity field will be used to save email or phone number.
- "sendOtpVia" field can be "phone" or "email" depending upon your choice of sending OTP via email or SMS. Accordingly you will have to provide information regarding email and SMS service in the "emailInfo" and "twilioInfo" fields respectively.
- For overriding the default email service (i.e gmail) and default SMS service (i.e gmail), refer to [this](#examples---passport-otp-example) example

## Examples - passport-otp-example

Developers using the popular [Loopback](https://loopback.io/) web framework can
refer to an [example](https://github.com/yash17525/loopback-project-authentication.git)
as a starting point for their own web applications.

