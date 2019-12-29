const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/otpDatabase');

const OtpSecret = require('./models/OtpSecret')
var secret = new OtpSecret({
    phone : 213,
    secret : 123
});

secret.save().then(()=>{
    if(!secret.isNew == false){
        return res.json({
            message:'some error occured, please try again'
        });
    }else{
        console.log('secret saved to database');
    }
});

OtpSecret.findOneAndDelete({phone:213}).then((result)=>{
    console.log(result);
});

