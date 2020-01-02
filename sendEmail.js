var nodemailer = require('nodemailer');

var sendMail = async function(email,password,recipentEmail,OTP){

    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: email+'s',
            pass: password
        }
    });
    
    var mailOptions = {
        from: email,
        to: recipentEmail,
        subject: 'Sending Email using Node.js',
        text: 'That is your OTP for login: '+ OTP
    };

    let result = await transporter.sendMail(mailOptions);
    return result;
}

module.exports = sendMail;