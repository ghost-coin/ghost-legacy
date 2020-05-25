/*
Bitcore import and consts
*/
const bitcore = require('bitcore-lib');
const Address = bitcore.Address;

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
const configNetwork = require('./config.json').networks[getNetworkID(network)];

const PayoutAddrs = configNetwork.payeeAddrs;
const OutputsToMake = PayoutAddrs.length;
const PaymentPerAddr =  configNetwork.amountToSplit / PayoutAddrs.length;
/*
Ghost network additions to bitcore
NOTE : Add network params changes here if prefixes are changed in chainparams
*/
function SetupGhostParams(){
    bitcore.Networks.add({
        name: 'regtest-ghost',
        alias: 'reg-ghost',
        pubkeyhash: 0x76,
        privatekey: 0x2e,
        scripthash: 0x7a,
        bech32prefix: 'rtpw',
        xpubkey: 0xe1427800,
        xprivkey: 0x04889478,
        networkMagic: 0x0b110907,
        port: 11938,
        dnsSeeds: []
    });

    bitcore.Networks.add({
        name: 'testnet-ghost',
        alias: 'test-ghost',
        pubkeyhash: 0x4B,
        privatekey: 0x2e,
        scripthash: 0x89,
        bech32prefix: 'tgstw',
        xpubkey: 0xe1427800,
        xprivkey: 0x04889478,
        networkMagic: 0x0b051108,
        port: 51938,
        dnsSeeds: []
    });
    
    bitcore.Networks.add({
        name: 'mainnet-ghost',
        alias: 'main-ghost',
        pubkeyhash: 0x38,
        privatekey: 0x6c,
        scripthash: 0x3c,
        bech32prefix: 'pw',
        xpubkey: 0x696e82d1,
        xprivkey: 0x8f1daeb8,
        networkMagic: 0xb4eff2fb,
        port: 51738,
        dnsSeeds: []
    });
}
/*
  Simple func to convert addr to hash160 required for genesisoutputs
*/
function GetHash160FromAddr(addr){
    const addrd = Address.fromString(addr);
    var script = bitcore.Script.buildPublicKeyHashOut(addrd).toString()
    script = script.split("0x").pop();//Remove all text before 0x prefix of hash160
    script = script.replace(" OP_EQUALVERIFY OP_CHECKSIG","");//Remove opcodes from output
    return script;
}

function getNetworkID(network){
    switch(network){
        case 'mainnet':
            return 0;
        case 'testnet':
            return 1;
        case 'regtest':
            return 2;
    }
}

// Setup params first
SetupGhostParams();

function generateGenesisOutputs(){
    var outputs = "";
    //Now prepare genesisOutputs
    for(var i=0;i<OutputsToMake;i++){
        outputs+= fillOutput(GetHash160FromAddr(PayoutAddrs[i]),PaymentPerAddr);
    }
    console.log(outputs)
}

function fillOutput(hash,amt){
    return `    std::make_pair("${hash}", ${amt} * COIN),\n`
}

generateGenesisOutputs()
