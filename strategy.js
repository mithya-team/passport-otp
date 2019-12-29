'use strict';

const Strategy = function (options, verify) {
    console.log('Strategy.constructor', options, verify);
    

}


Strategy.prototype.authenticate = function(req, options) {
    console.log('Strategy.prototype.authenticate', req, options);
}


// Expose constructor.
module.exports = Strategy;