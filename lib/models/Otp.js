module.exports = Otp;
var _ = require("lodash");
function Otp(Otp) {
  // console.log("aaa")

  Otp.observe("before save", (ctx,next) => {
    const instance = ctx.instance || ctx.data;
    if (ctx.isNewInstance) {
      _.set(instance, `attempt.lastAttempt`, new Date());
    }
    next();
  });
  

  var otpSetup = Otp.setup;
  Otp.setup = function() {
    otpSetup.apply(this, arguments);
    var Otp = this;
  };

  
  return Otp;
}
