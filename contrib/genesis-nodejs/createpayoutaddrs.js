var run = function() {
    var RpcClient = require('bitcoind-rpc');
    var addrs = [];
    const addrsneeded = 20;
    var config = {
      protocol: 'http',
      user: 'user',
      pass: 'pass',
      host: '127.0.0.1',
      port: '51936',
    };
  
    // config can also be an url, e.g.:
    // var config = 'http://user:pass@127.0.0.1:18332';
  
    var rpc = new RpcClient(config);  
    function getPaymentaddresses() {
        for(var i=0;i<addrsneeded;i++){
            rpc.getNewAddress(function (err, ret) {
                console.log(ret)
                if(err){
                    console.error(err)
                }
                addrs.push(ret.result.toString());
                console.log(addrs);

            });
        }

    }
    getPaymentaddresses();
};
run()