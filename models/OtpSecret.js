const mongoose = require('mongoose');
const Schema = mongoose.Schema;


const OtpSecretSchema  = new Schema({
    phone : String,
    secret : String
});

const OtpSecret = mongoose.model('OtpSecret',OtpSecretSchema);

module.exports = OtpSecret; 