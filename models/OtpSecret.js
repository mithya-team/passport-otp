const mongoose = require('mongoose');
const Schema = mongoose.Schema;


const OtpSecretSchema  = new Schema({
    phone : String,
    secret : Number
});

const OtpSecret = mongoose.model('OtpSecret',OtpSecretSchema);

module.exports = OtpSecret; 