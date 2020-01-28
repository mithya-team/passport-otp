module.exports = Otp;
function Otp(Otp) {
  // console.log("aaa")

  Otp.test=()=>{
    return "lol"
  }

  Otp.remoteMethod('test',
        {
            description: 'test',
            accepts: [
                // { arg: 'post', type: 'object', http: { source: "body" } },
                // { arg: 'req', type: 'object', http: { source: "req" } }
            ],
            returns: {
                arg: 'msg',
                type: 'object',
                root: true,
            },
            http: { path: '/test', verb: 'GET' }
        }
    );
  return Otp;
}
