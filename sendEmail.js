var nodemailer = require('nodemailer');

var sendMail = async function (emailInfo, recipentEmail, OTP) {
    let email = emailInfo[0].gmail;
    let password = emailInfo[1].password;
    var subject = !emailInfo[2].emailSubject;
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: email,
            pass: password
        }
    });


    var mailOptions = {
        from: email,
        to: recipentEmail,
        subject: subject,
        text: 'That is your OTP for login: ' + OTP
    };

    let result = await transporter.sendMail(mailOptions);
    return result;
}

module.exports = sendMail;