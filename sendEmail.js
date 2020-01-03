var nodemailer = require('nodemailer');
class EmailService {
    constructor(emailInfo) {
        this._email = emailInfo.gmail;
        this._password = emailInfo.password;
        this._subject = emailInfo.emailSubject;

        if (!this._email || !this._password || !this._subject)
            throw new Error(
                '\nPlease provide all the fields of "emailInfo" in the provider.json file.\n Example--------------------------------->\n'
                + '```\n"emailInfo": {\n'
                + '"gmail": "anonymous@gmail.com",\n'
                + '"password": "xxxxxxxxxxxx",\n'
                + '"emailSubject": "OTP for login to <YOUR APPLICATION NAME>"\n}\n```\n');

        this._transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: this._email,
                pass: this._password
            }
        });
    }
    sendMessage = async function (recipentEmail, OTP) {
        let mailOptions = {
            from: this._email,
            to: recipentEmail,
            subject: this._subject,
            text: 'That is your OTP for login: ' + OTP
        };

        let result = await this._transporter.sendMail(mailOptions);
        return result;
    }
}

module.exports = EmailService;