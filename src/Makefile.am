# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(HARDENED_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS) $(GPROF_CXXFLAGS) $(SANITIZER_CXXFLAGS)
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) $(HARDENED_CPPFLAGS)
AM_CFLAGS = $(AM_CXXFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

BITCOIN_INCLUDES=-I$(builddir) $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += $(UNIVALUE_CFLAGS)
BLS_LIBS=-lchiabls -lgmp

LIBGHOST_SERVER=libghost_server.a
LIBGHOST_COMMON=libghost_common.a
LIBGHOST_CONSENSUS=libghost_consensus.a
LIBGHOST_CLI=libghost_cli.a
LIBGHOST_UTIL=libghost_util.a
LIBGHOST_CRYPTO_BASE=crypto/libghost_crypto_base.a
LIBGHOSTQT=qt/libghostqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBGHOST_SMSG=libghost_smsg.a
LIBGHOST_MNEMONIC=libghost_mnemonic.a

if ENABLE_ZMQ
LIBGHOST_ZMQ=libghost_zmq.a
endif
if BUILD_BITCOIN_LIBS
LIBGHOSTCONSENSUS=libghostconsensus.la
endif
if ENABLE_WALLET
LIBGHOST_WALLET=libghost_wallet.a
LIBGHOST_WALLET_TOOL=libghost_wallet_tool.a
endif
if ENABLE_USBDEVICE
LIBGHOST_USBDEVICE=libghost_usbdevice.a
endif

LIBGHOST_CRYPTO= $(LIBGHOST_CRYPTO_BASE)
if ENABLE_SSE41
LIBGHOST_CRYPTO_SSE41 = crypto/libghost_crypto_sse41.a
LIBGHOST_CRYPTO += $(LIBGHOST_CRYPTO_SSE41)
endif
if ENABLE_AVX2
LIBGHOST_CRYPTO_AVX2 = crypto/libghost_crypto_avx2.a
LIBGHOST_CRYPTO += $(LIBGHOST_CRYPTO_AVX2)
endif
if ENABLE_SHANI
LIBGHOST_CRYPTO_SHANI = crypto/libghost_crypto_shani.a
LIBGHOST_CRYPTO += $(LIBGHOST_CRYPTO_SHANI)
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*.h) $(wildcard secp256k1/src/*.c) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBGHOST_CRYPTO) \
  $(LIBGHOST_UTIL) \
  $(LIBGHOST_COMMON) \
  $(LIBGHOST_CONSENSUS) \
  $(LIBGHOST_SERVER) \
  $(LIBGHOST_CLI) \
  $(LIBGHOST_WALLET) \
  $(LIBGHOST_WALLET_TOOL) \
  $(LIBGHOST_USBDEVICE) \
  $(LIBGHOST_SMSG) \
  $(LIBGHOST_MNEMONIC) \
  $(LIBGHOST_ZMQ)

lib_LTLIBRARIES = $(LIBGHOSTCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += ghostd
endif

if BUILD_BITCOIN_CLI
  bin_PROGRAMS += ghost-cli
endif
if BUILD_BITCOIN_TX
  bin_PROGRAMS += ghost-tx
endif
if ENABLE_WALLET
if BUILD_BITCOIN_WALLET
  bin_PROGRAMS += ghost-wallet
endif
endif

.PHONY: FORCE check-symbols check-security
# bitcoin core #
BITCOIN_CORE_H = \
  addrdb.h \
  rctindex.h \
  addrman.h \
  attributes.h \
  banman.h \
  base58.h \
  bech32.h \
  bloom.h \
  blockencodings.h \
  blockfilter.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  chainparamsimport.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/assumptions.h \
  compat/byteswap.h \
  compat/cpuid.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/tx_check.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  ctpl.h \
  flatfile.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  index/base.h \
  index/blockfilterindex.h \
  index/txindex.h \
  indirectmap.h \
  init.h \
  anon.h \
  blind.h \
  interfaces/chain.h \
  interfaces/handler.h \
  interfaces/node.h \
  interfaces/wallet.h \
  key.h \
  key/stealth.h \
  key/extkey.h \
  key/types.h \
  key/keyutil.h \
  key_io.h \
  dbwrapper.h \
  limitedmap.h \
  logging.h \
  logging/timer.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_permissions.h \
  net_processing.h \
  net_types.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  node/coin.h \
  node/coinstats.h \
  node/context.h \
  node/psbt.h \
  node/transaction.h \
  node/utxo_snapshot.h \
  noui.h \
  optional.h \
  outputtype.h \
  policy/feerate.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  policy/settings.h \
  pow.h \
  pos/kernel.h \
  pos/miner.h \
  protocol.h \
  psbt.h \
  random.h \
  randomenv.h \
  reverse_iterator.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/rawtransaction_util.h \
  rpc/register.h \
  rpc/request.h \
  rpc/server.h \
  rpc/util.h \
  rpc/rpcutil.h \
  scheduler.h \
  script/descriptor.h \
  script/keyorigin.h \
  script/sigcache.h \
  script/sign.h \
  script/signingprovider.h \
  script/standard.h \
  script/ismine.h \
  shutdown.h \
  streams.h \
  smsg/db.h \
  smsg/crypter.h \
  smsg/net.h \
  smsg/smessage.h \
  smsg/rpcsmessage.h \
  support/allocators/mt_pooled_secure.h \
  support/allocators/pooled_secure.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  undo.h \
  util/asmap.h \
  util/bip32.h \
  util/bytevectorhash.h \
  util/check.h \
  util/error.h \
  util/fees.h \
  util/golombrice.h \
  util/spanparsing.h \
  util/system.h \
  util/macros.h \
  util/memory.h \
  util/message.h \
  util/moneystr.h \
  util/rbf.h \
  util/settings.h \
  util/string.h \
  util/threadnames.h \
  util/time.h \
  util/translation.h \
  util/url.h \
  util/vector.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  versionbitsinfo.h \
  walletinitinterface.h \
  wallet/coincontrol.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/ismine.h \
  wallet/load.h \
  wallet/rpcwallet.h \
  wallet/scriptpubkeyman.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/wallettool.h \
  wallet/walletutil.h \
  wallet/coinselection.h \
  wallet/rpchdwallet.h \
  wallet/hdwalletdb.h \
  wallet/hdwallettypes.h \
  wallet/hdwallet.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  zmq/zmqrpc.h \
  usbdevice/usbdevice.h \
  usbdevice/rpcusbdevice.h \
  insight/addressindex.h \
  insight/spentindex.h \
  insight/timestampindex.h \
  insight/csindex.h \
  insight/insight.h \
  insight/rpc.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libghost_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between bitcoind and bitcoin-qt
# Contains code accessing mempool and chain state that is meant to be separated
# from wallet and gui code (see node/README.md). Shared code should go in
# libbitcoin_common or libbitcoin_util libraries, instead.
libghost_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libghost_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_server_a_SOURCES = \
  addrdb.cpp \
  addrman.cpp \
  banman.cpp \
  blockencodings.cpp \
  blockfilter.cpp \
  chain.cpp \
  consensus/tx_verify.cpp \
  flatfile.cpp \
  httprpc.cpp \
  httpserver.cpp \
  index/base.cpp \
  index/blockfilterindex.cpp \
  index/txindex.cpp \
  interfaces/chain.cpp \
  interfaces/node.cpp \
  init.cpp \
  dbwrapper.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  node/coin.cpp \
  node/coinstats.cpp \
  node/context.cpp \
  node/psbt.cpp \
  node/transaction.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/rbf.cpp \
  policy/settings.cpp \
  pow.cpp \
  pos/kernel.cpp \
  rest.cpp \
  rpc/anon.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  rpc/client.cpp \
  rpc/rpcutil.cpp \
  rpc/util.cpp \
  script/sigcache.cpp \
  shutdown.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  insight/insight.cpp \
  insight/rpc.cpp \
  $(BITCOIN_CORE_H)

if ENABLE_WALLET
libghost_server_a_SOURCES += wallet/init.cpp
endif
if !ENABLE_WALLET
libghost_server_a_SOURCES += dummywallet.cpp
endif

if ENABLE_ZMQ
libghost_zmq_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libghost_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp
endif

if ENABLE_USBDEVICE
libghost_usbdevice_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(AM_CPPFLAGS) $(PROTOBUF_CFLAGS)
libghost_usbdevice_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_usbdevice_a_CFLAGS = -DHAVE_HIDAPI $(AM_CFLAGS) $(PIE_FLAGS)
libghost_usbdevice_a_SOURCES = \
  usbdevice/usbwrapper.cpp \
  usbdevice/usbwrapper.h \
  usbdevice/ledger/btchipApdu.h \
  usbdevice/ledger/ledgerLayer.h \
  usbdevice/ledger/ledgerLayer.c \
  usbdevice/ledger/dongleCommHidHidapi.h \
  usbdevice/ledger/dongleCommHidHidapi.c \
  usbdevice/usbdevice.cpp \
  usbdevice/debugdevice.h \
  usbdevice/debugdevice.cpp \
  usbdevice/ledgerdevice.h \
  usbdevice/ledgerdevice.cpp \
  usbdevice/trezor/messages.proto \
  usbdevice/trezor/messages-common.proto \
  usbdevice/trezor/messages-management.proto \
  usbdevice/trezor/messages-bitcoin.proto \
  usbdevice/trezordevice.h \
  usbdevice/trezordevice.cpp \
  usbdevice/rpcusbdevice.cpp
nodist_libghost_usbdevice_a_SOURCES = \
  usbdevice/trezor/messages.pb.h \
  usbdevice/trezor/messages.pb.cc \
  usbdevice/trezor/messages-common.pb.h \
  usbdevice/trezor/messages-common.pb.cc \
  usbdevice/trezor/messages-management.pb.h \
  usbdevice/trezor/messages-management.pb.cc \
  usbdevice/trezor/messages-bitcoin.pb.h \
  usbdevice/trezor/messages-bitcoin.pb.cc
BUILT_SOURCES = $(nodist_libghost_usbdevice_a_SOURCES)
endif

# wallet: shared between bitcoind and bitcoin-qt, but only linked
# when wallet enabled
libghost_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libghost_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_wallet_a_SOURCES = \
  interfaces/wallet.cpp \
  wallet/coincontrol.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/load.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/scriptpubkeyman.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/hdwallet.cpp \
  wallet/hdwallettypes.cpp \
  wallet/hdwalletdb.cpp \
  wallet/rpchdwallet.cpp \
  blind.cpp \
  key/stealth.cpp \
  pos/miner.cpp \
  policy/rbf.cpp \
  wallet/walletutil.cpp \
  wallet/coinselection.cpp \
  $(BITCOIN_CORE_H)

libghost_wallet_tool_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libghost_wallet_tool_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_wallet_tool_a_SOURCES = \
  wallet/wallettool.cpp \
  $(BITCOIN_CORE_H)

# crypto primitives library
crypto_libghost_crypto_base_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libghost_crypto_base_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libghost_crypto_base_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha_poly_aead.h \
  crypto/chacha_poly_aead.cpp \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hkdf_sha256_32.cpp \
  crypto/hkdf_sha256_32.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/poly1305.h \
  crypto/poly1305.cpp \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/siphash.cpp \
  crypto/siphash.h

if USE_ASM
crypto_libghost_crypto_base_a_SOURCES += crypto/sha256_sse4.cpp
endif

crypto_libghost_crypto_sse41_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libghost_crypto_sse41_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libghost_crypto_sse41_a_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libghost_crypto_sse41_a_CPPFLAGS += -DENABLE_SSE41
crypto_libghost_crypto_sse41_a_SOURCES = crypto/sha256_sse41.cpp

crypto_libghost_crypto_avx2_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libghost_crypto_avx2_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libghost_crypto_avx2_a_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libghost_crypto_avx2_a_CPPFLAGS += -DENABLE_AVX2
crypto_libghost_crypto_avx2_a_SOURCES = crypto/sha256_avx2.cpp

crypto_libghost_crypto_shani_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libghost_crypto_shani_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libghost_crypto_shani_a_CXXFLAGS += $(SHANI_CXXFLAGS)
crypto_libghost_crypto_shani_a_CPPFLAGS += -DENABLE_SHANI
crypto_libghost_crypto_shani_a_SOURCES = crypto/sha256_shani.cpp

# consensus: shared between all executables that validate any consensus rules.
libghost_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libghost_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/tx_check.cpp \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/bitcoinconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  span.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  util/strencodings.cpp \
  util/strencodings.h \
  version.h

# common: shared between bitcoind, and bitcoin-qt and non-server tools
libghost_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libghost_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_common_a_SOURCES = \
  bls/bls.cpp \
  bls/bls.h \
  base58.cpp \
  bech32.cpp \
  bloom.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  anon.cpp \
  blind.cpp \
  key.cpp \
  key/keyutil.cpp \
  key/extkey.cpp \
  key/stealth.cpp \
  smsg/crypter.cpp \
  key_io.cpp \
  merkleblock.cpp \
  netaddress.cpp \
  netbase.cpp \
  net_permissions.cpp \
  outputtype.cpp \
  policy/feerate.cpp \
  policy/policy.cpp \
  protocol.cpp \
  psbt.cpp \
  rpc/rawtransaction_util.cpp \
  rpc/util.cpp \
  scheduler.cpp \
  script/descriptor.cpp \
  script/sign.cpp \
  script/signingprovider.cpp \
  script/standard.cpp \
  versionbitsinfo.cpp \
  warnings.cpp \
  $(BITCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libghost_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libghost_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_util_a_SOURCES = \
  bls/bls_batchverifier.h \
  bls/bls_ies.cpp \
  bls/bls_ies.h \
  bls/bls_worker.cpp \
  bls/bls_worker.h \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity_fdelt.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  interfaces/handler.cpp \
  logging.cpp \
  random.cpp \
  randomenv.cpp \
  rpc/request.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util/asmap.cpp \
  util/bip32.cpp \
  util/bytevectorhash.cpp \
  util/error.cpp \
  util/fees.cpp \
  util/system.cpp \
  util/message.cpp \
  util/moneystr.cpp \
  util/rbf.cpp \
  util/settings.cpp \
  util/threadnames.cpp \
  util/spanparsing.cpp \
  util/strencodings.cpp \
  util/string.cpp \
  util/time.cpp \
  $(BITCOIN_CORE_H)

if USE_LIBEVENT
libghost_util_a_SOURCES += util/url.cpp
endif

libghost_smsg_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libghost_smsg_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_smsg_a_CFLAGS = $(AM_CFLAGS) $(PIE_FLAGS)
libghost_smsg_a_SOURCES = \
  lz4/lz4.h \
  lz4/lz4.c \
  xxhash/xxhash.h \
  xxhash/xxhash.c \
  interfaces/handler.cpp \
  smsg/crypter.cpp \
  smsg/keystore.h \
  smsg/keystore.cpp \
  smsg/db.cpp \
  smsg/smessage.cpp \
  smsg/rpcsmessage.cpp


libghost_mnemonic_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libghost_mnemonic_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_mnemonic_a_CFLAGS = $(AM_CFLAGS) $(PIE_FLAGS)
libghost_mnemonic_a_SOURCES = \
  unilib/uninorms.h \
  unilib/utf8.h \
  unilib/uninorms.cpp \
  unilib/utf8.cpp \
  key/wordlists/chinese_simplified.h \
  key/wordlists/chinese_traditional.h \
  key/wordlists/english.h \
  key/wordlists/french.h \
  key/wordlists/japanese.h \
  key/wordlists/spanish.h \
  key/wordlists/italian.h \
  key/wordlists/korean.h \
  key/wordlists/czech.h \
  key/mnemonic.h \
  key/mnemonic.cpp \
  rpc/mnemonic.cpp

if GLIBC_BACK_COMPAT
libghost_util_a_SOURCES += compat/glibc_compat.cpp
AM_LDFLAGS += $(COMPAT_LDFLAGS)
endif

# cli: shared between bitcoin-cli and bitcoin-qt
libghost_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
libghost_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libghost_cli_a_SOURCES = \
  compat/stdin.h \
  compat/stdin.cpp \
  rpc/client.cpp \
  $(BITCOIN_CORE_H)


nodist_libghost_util_a_SOURCES = $(srcdir)/obj/build.h
#

# bitcoind binary #
ghostd_SOURCES = bitcoind.cpp
ghostd_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
ghostd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
ghostd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
ghostd_SOURCES += bitcoind-res.rc
endif

# Libraries below may be listed more than once to resolve circular dependencies (see
# https://eli.thegreenplace.net/2013/07/09/library-order-in-static-linking#circular-dependency)
ghostd_LDADD = \
  $(LIBGHOST_SERVER) \
  $(LIBGHOST_WALLET) \
  $(LIBGHOST_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBGHOST_UTIL) \
  $(LIBGHOST_ZMQ) \
  $(LIBGHOST_CONSENSUS) \
  $(LIBGHOST_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBGHOST_SMSG) \
  $(LIBGHOST_MNEMONIC) \
  $(LIBGHOST_USBDEVICE)

ghostd_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(BLS_LIBS)
if ENABLE_USBDEVICE
ghostd_LDADD += $(USB_LIBS) $(HIDAPI_LIBS) $(PROTOBUF_LIBS)
endif

# bitcoin-cli binary #
#$(BITCOIN_CLI_NAME)_SOURCES = bitcoin-cli.cpp
ghost_cli_SOURCES = bitcoin-cli.cpp
ghost_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
ghost_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
ghost_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
ghost_cli_SOURCES += bitcoin-cli-res.rc
endif

ghost_cli_LDADD = \
  $(LIBGHOST_CLI) \
  $(LIBUNIVALUE) \
  $(LIBGHOST_UTIL) \
  $(LIBGHOST_CRYPTO)

ghost_cli_LDADD += $(BOOST_LIBS) $(EVENT_LIBS) $(BLS_LIBS)
#

# bitcoin-tx binary #
ghost_tx_SOURCES = bitcoin-tx.cpp
ghost_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
ghost_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
ghost_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
ghost_tx_SOURCES += bitcoin-tx-res.rc
endif

ghost_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBGHOST_COMMON) \
  $(LIBGHOST_UTIL) \
  $(LIBGHOST_CONSENSUS) \
  $(LIBGHOST_CRYPTO) \
  $(LIBSECP256K1)

ghost_tx_LDADD += $(BOOST_LIBS) $(BLS_LIBS)
#

# bitcoin-wallet binary #
ghost_wallet_SOURCES = bitcoin-wallet.cpp
ghost_wallet_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
ghost_wallet_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
ghost_wallet_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
ghost_wallet_SOURCES += bitcoin-wallet-res.rc
endif


ghost_wallet_LDADD = \
  $(LIBGHOST_WALLET_TOOL) \
  $(LIBGHOST_WALLET) \
  $(LIBGHOST_SERVER) \
  $(LIBGHOST_COMMON) \
  $(LIBGHOST_CONSENSUS) \
  $(LIBGHOST_UTIL) \
  $(LIBGHOST_CRYPTO) \
  $(LIBGHOST_SMSG) \
  $(LIBGHOST_MNEMONIC) \
  $(LIBGHOST_USBDEVICE) \
  $(LIBGHOST_ZMQ) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBUNIVALUE)

ghost_wallet_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(MINIUPNPC_LIBS) $(ZMQ_LIBS)
if ENABLE_USBDEVICE
ghost_wallet_LDADD += $(USB_LIBS) $(HIDAPI_LIBS) $(PROTOBUF_LIBS)
endif
#

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/ghostconsensus.h
libghostconsensus_la_SOURCES = support/cleanse.cpp $(crypto_libghost_crypto_base_a_SOURCES) $(libghost_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libghostconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libghostconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libghostconsensus_la_LIBADD = $(LIBSECP256K1) $(BOOST_LIBS) $(BLS_LIBS)
libghostconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL
libghostconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

IMMER_DIST = immer

EXTRA_DIST = $(CTAES_DIST)
EXTRA_DIST += $(IMMER_DIST)


config/bitcoin-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/bitcoin-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/bitcoin-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/bitcoin-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
if TARGET_DARWIN
	@echo "Checking macOS dynamic libraries..."
	$(AM_V_at) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if TARGET_WINDOWS
	@echo "Checking Windows dynamic libraries..."
	$(AM_V_at) OBJDUMP=$(OBJDUMP) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) OTOOL=$(OTOOL) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

if ENABLE_USBDEVICE
%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<
endif

if EMBEDDED_LEVELDB
include Makefile.crc32c.include
include Makefile.leveldb.include
endif

include Makefile.test_util.include
include Makefile.test_fuzz.include

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
