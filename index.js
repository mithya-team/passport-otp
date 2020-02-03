"use strict";

var loopback = require("loopback");
var DataModel = loopback.PersistedModel || loopback.DataModel;

function loadModel(jsonFile) {
  var modelDefinition = require(jsonFile);
  return DataModel.extend(modelDefinition.name, modelDefinition.properties, {
    relations: modelDefinition.relations
  });
}



// Load modules.
const Strategy = require("./strategy");

// Expose Strategy.
exports = module.exports = Strategy;

// Export Otp Model
var OtpModel = loadModel("./lib/models/Otp.json");
exports.Otp = module.exports.Otp = require("./lib/models/Otp")(OtpModel);
exports.Otp.autoAttach = "db";

//Export Twilio Model
var TwilioModel = loadModel("./lib/models/Twilio.json");
exports.Twilio = module.exports.Twilio = require("./lib/models/Twilio")(TwilioModel);
exports.Twilio.autoAttach = "db";