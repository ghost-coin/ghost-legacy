const commander = require('commander');
/*
Command line args
*/

commander
  .version('1.0.0', '-v, --version')
  .usage('[OPTIONS]...')
  .option('-n, --network <name>', 'Network to generate for', 'mainnet')
  .parse(process.argv);

const network = commander.network;

/*
Config consts and coin related consts
*/
const configNetwork = require('./config.json').networks[network];

/*
Main func
*/
var GetNewAddresses = function() {
    
    var RpcClient = require('bitcoind-rpc');
    var addrs = [];
    const addrsneeded = 20;
    
    // config can also be an url, e.g.:
    // var config = 'http://user:pass@127.0.0.1:18332';
    
    var rpc = new RpcClient(configNetwork.config);  
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
GetNewAddresses()