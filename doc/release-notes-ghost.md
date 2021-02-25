0.19.1.6
==============

 - [Params] Update checkpoints and chaintxdata.
 - [Params] Remove SetLastImportHeight.
 - [Params] Update Ext key prefixes.
 - [Wallet/Params] Add migration code for new bip44 prefix.
 - [Params] Add more seeds to chainparamsbase.cpp.

0.19.1.7
==============
AkshayCM (33):
- [Tests] Add inital extkey test fixes
- More fixes to extkey_tests
- Prevent duplicate address error on script addrs.
- Add todo comment on remaining test changes for mainnet.
- [Seeds] Update seeds from seeder
- [LevelDB] Revert leveldb changes done without subtree merge
- Add newline
- Changes to conform to CI checks
- Fix final check failures
- Fix host prefix to ghost
- Fix test runs
- [RPC] Add burn command
- Add more info to getcoldstakinginfo
- Remove unecessary cs_main lock and minor fixes
- WIP gvr pay change code
- Use DecodeDestination for devsettings and fix small bug
- Draft gvr one time payout code
- Cleanup and lint fixes
- Fix trailing whitespace
- Fix shellcheck install
- Fix lint errors
- Integrate mypy changes from upstream
- Set heights for Testnet and mainnet deployment
- Fix unit test for blockreward at height
- Fix sync and reindex bug due to devfee calc
- Set devfee with as float properly on testnet
- Decrease hardfork height on testnet
- [POS] Use LWMA for block difficulty algo and update hardfork heights.
- Minor fixes to lwma code
- Finalize upgrade params for mainnet
- Fix lint errors due to tabs
- Use RPCHelpMan for getavgblocktime
- Bump version and change website for v0.19.1.7

reborn1002 (1):
- RPC warning for duplicate address sends + formatting

0.19.1.8
==============
- Enforce GVR onetime payout on payout height
- Disconnect old version after payout height

0.19.1.9
==============
barrystyle (2):
- Shift GVT payment address to GVR-operated address, refactor method to do so.
- Disconnect old version after fork height

0.19.1.10
==============
barrystyle (backported from particl):
- Emergency hardfork release
- Disables anon and blind transactions
