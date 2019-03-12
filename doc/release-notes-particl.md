Master
==============


0.18.0.6 rc1
==============

- Fixed failure when sending all blind to part.


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
