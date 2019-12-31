var nodemailer = require('nodemailer');

var sendMail = function(email,password,recipentEmail,OTP){

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
        subject: 'Sending Email using Node.js',
        text: 'That is your OTP for login: '+ OTP
    };
    
    transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

module.exports = sendMail;