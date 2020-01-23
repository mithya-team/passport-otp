"use strict";

var loopback = require("loopback");
var DataModel = loopback.PersistedModel || loopback.DataModel;

function loadModel(jsonFile) {
  var modelDefinition = require(jsonFile);
  return DataModel.extend(modelDefinition.name, modelDefinition.properties, {
    relations: modelDefinition.relations
  });
}

//Export Otp Model
var OtpModel = loadModel("./lib/models/Otp.json");
exports.Otp = module.exports.Otp = require("./lib/models/Otp")(OtpModel);
exports.Otp.autoAttach = "db";

// Load modules.
const Strategy = require("./strategy");

// Expose Strategy.
exports = module.exports = Strategy;
