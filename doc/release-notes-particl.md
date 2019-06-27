0.18.0.11
==============

- Fixed regression causing unloadwallet to fail.


0.18.0.10
==============

- Fixed avoidpartialspends.
- Testnet fork scheduled for 2019-07-01 12:00:00 UTC
  - Enable variable difficulty for smsg free messages.
- Mainnet fork scheduled for 2019.07.16-12:00:00 UTC
  - Enable bulletproof rangeproofs.
  - Enable RingCT transactions.
  - Enable variable fee rate for smsg paid messages.
  - Enable variable difficulty for smsg free messages.


0.18.0.9
==============

- pruneorphanedblocks shows shutdown warning if not in test mode.
- Fixed Qt 'Request payment' button greyed out after importing mnemonic.


0.18.0.8
==============

- Fixed issue where clearing the rewardaddress requires a restart.
- Fixed regression where disablewallet required nosmsg also.
- Fixed getrawtransaction failing where scripts are nonstandard with OP_ISCOINSTAKE.
- New balance category for immature anon coin.


0.18.0.7
==============

- Fixed regression causing wallet catch-up rescan to never trigger.
- New checkpoints.


0.18.0.6 rc2
==============

- Fixed regression when sending all blind to part.


0.18.0.6 rc1
==============

SMSG won't connect to nodes running a version below 0.18.0.6

- Fixed failure when sending all blind to part.
- smsgbuckets: Add total only mode
- SMSG: Difficulty can be adjusted by stakers.
- SMSG: Messages can be created and imported without being transmitted.
- SMSG: Messages can be sent without being stored to the outbox.


0.18.0.5 rc1
==============

0.18.0.3 or above required for testnet fork at 2019-02-16 12:00:00 UTC.

- filtertransactions: Display fee when type is 'internal_transfer'.
- promptunlockdevice and unlockdevice added for Trezor hardware wallet.
- signmessage / verifymessage: Add sign and verify using 256bit addresses.
- Wallet won't search smsg for unknown pubkeys when sending.
- New rewindrangeproof rpc command.
- Fixed initial block download issues.
- Converted contrib/linearize.
- Updated DNS seeds.
- New checkpoint data.
- New branding.


0.18.0.4 Alpha
==============
For Testnet.

0.18.0.3 or above required for testnet fork at 2019-02-16 12:00:00 UTC.

- Fixed lockunspent crash in market tests.


0.18.0.3 Alpha
==============
For Testnet.

0.18.0.3 or above required for testnet fork at 2019-02-16 12:00:00 UTC.

- Enables variable smsg fee after fork.
- Enables bullet proof range proofs after fork.
- Enables p2sh in coldstake spend script after fork.



0.17.1.4
==============
For mainnet only.

0.17.1.2 or above required for mainnet fork at 2019-03-01 12:00:00 UTC.

- Fixed initial block download issues.
- Updated DNS seeds.
- New checkpoint data.


0.17.1.3
==============
For mainnet only.

0.17.1.2 or above required for mainnet fork at 2019-03-01 12:00:00 UTC.

- Removed smsg fee limit, allowing larger messages to be valid for more
  time.


0.17.1.2
==============
For mainnet only.

0.17.1.2 or above required for mainnet fork at 2019-03-01 12:00:00 UTC.

- This release will enable paid secure messaging on mainnet after fork
  scheduled for 2019-03-01 12:00:00 UTC.
