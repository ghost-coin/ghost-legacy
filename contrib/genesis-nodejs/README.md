## Genesis-nodejs
This is a simple script mainly to help setup a new network based on Particl codebase.

## How to setup config.json
- Run createpayoutaddrs.js,this will give you a array of newly generated addresses from daemon.
- paste that to the config.json payeeaddrs array.Make sure to paste it in the proper index,ie 0 for mainnet,1 for testnet,2 for regtest.

## How to get genesisoutputs code:
- run the generategenesisouts.js via `node generategenesisouts.js  -n testnet` where testnet is your desired network.

