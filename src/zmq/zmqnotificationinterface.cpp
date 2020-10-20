// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <zmq/zmqnotificationinterface.h>
#include <zmq/zmqpublishnotifier.h>
#include <zmq/zmqutil.h>

#include <zmq.h>

#include <validation.h>
#include <util/system.h>
#include <netbase.h>


bool CZMQNotificationInterface::IsWhitelistedRange(const CNetAddr &addr) {
    for (const CSubNet& subnet : vWhitelistedRange) {
        if (subnet.Match(addr))
            return true;
    }
    return false;
}

void CZMQNotificationInterface::ThreadZAP()
{
    // https://rfc.zeromq.org/spec:27/ZAP/
    assert(pcontext);
    void *sock = zmq_socket(pcontext, ZMQ_REP);
    zmq_bind(sock, "inproc://zeromq.zap.01");
    zapActive = true;

    uint8_t buf[10][1024];
    size_t nb[10];
    while (zapActive) {
        zmq_pollitem_t poll_items[] = { {sock, 0, ZMQ_POLLIN, 0} };
        int rc = zmq_poll(poll_items, 1, 500);
        if (!(rc > 0 && poll_items[0].revents & ZMQ_POLLIN)) {
            continue;
        }

        size_t nParts = 0;
        int more;
        size_t size = sizeof(int);
        do {
            size_t b = nParts <= 9 ? nParts : 9; // read any extra messages into last chunk
            nb[b] = zmq_recv(sock, buf[b], sizeof(buf[b]), 0);
            zmq_getsockopt(sock, ZMQ_RCVMORE, &more, &size);
            nParts++;
        } while (more);

        if (nParts < 5) { // Too few parts to be valid
            continue;
        }

        if (nb[0] != 3 || memcmp(buf[0], "1.0", 3) != 0) {
            continue;
        }

        std::string address((char*)buf[3], nb[3]);

        bool fAccept = true;
        if (vWhitelistedRange.size() > 0) {
            CNetAddr addr;
            if (!LookupHost(address.c_str(), addr, false)) {
                fAccept = false;
            } else {
                fAccept = IsWhitelistedRange(addr);
            }
        }

        LogPrint(BCLog::ZMQ, "zmq: Connection request from %s %s.\n", address, fAccept ? "accepted" : "denied");

        zmq_send(sock, buf[0], nb[0], ZMQ_SNDMORE);                 // version "1.0"
        zmq_send(sock, buf[1], nb[1], ZMQ_SNDMORE);                 // request id
        zmq_send(sock, fAccept ? "200" : "400", 3, ZMQ_SNDMORE);    // status code
        zmq_send(sock, NULL, 0, ZMQ_SNDMORE);                       // status text
        zmq_send(sock, NULL, 0, ZMQ_SNDMORE);                       // user id
        zmq_send(sock, NULL, 0, 0);                                 // metadata
    }

    zmq_close(sock);
}

CZMQNotificationInterface::CZMQNotificationInterface() : pcontext(nullptr)
{
}

CZMQNotificationInterface::~CZMQNotificationInterface()
{
    Shutdown();
}

std::list<const CZMQAbstractNotifier*> CZMQNotificationInterface::GetActiveNotifiers() const
{
    std::list<const CZMQAbstractNotifier*> result;
    for (const auto& n : notifiers) {
        result.push_back(n.get());
    }
    return result;
}

CZMQNotificationInterface* CZMQNotificationInterface::Create()
{
    std::map<std::string, CZMQNotifierFactory> factories;
    factories["pubhashblock"] = CZMQAbstractNotifier::Create<CZMQPublishHashBlockNotifier>;
    factories["pubhashtx"] = CZMQAbstractNotifier::Create<CZMQPublishHashTransactionNotifier>;
    factories["pubrawblock"] = CZMQAbstractNotifier::Create<CZMQPublishRawBlockNotifier>;
    factories["pubrawtx"] = CZMQAbstractNotifier::Create<CZMQPublishRawTransactionNotifier>;
    factories["pubsequence"] = CZMQAbstractNotifier::Create<CZMQPublishSequenceNotifier>;

    factories["pubhashwtx"] = CZMQAbstractNotifier::Create<CZMQPublishHashWalletTransactionNotifier>;
    factories["pubsmsg"] = CZMQAbstractNotifier::Create<CZMQPublishSMSGNotifier>;

    std::list<std::unique_ptr<CZMQAbstractNotifier>> notifiers;
    for (const auto& entry : factories)
    {
        std::string arg("-zmq" + entry.first);
        const auto& factory = entry.second;
        for (const std::string& address : gArgs.GetArgs(arg)) {
            std::unique_ptr<CZMQAbstractNotifier> notifier = factory();
            notifier->SetType(entry.first);
            notifier->SetAddress(address);
            notifier->SetOutboundMessageHighWaterMark(static_cast<int>(gArgs.GetArg(arg + "hwm", CZMQAbstractNotifier::DEFAULT_ZMQ_SNDHWM)));
            notifiers.push_back(std::move(notifier));
        }
    }

    if (!notifiers.empty())
    {
        std::unique_ptr<CZMQNotificationInterface> notificationInterface(new CZMQNotificationInterface());
        notificationInterface->notifiers = std::move(notifiers);

        if (notificationInterface->Initialize()) {
            return notificationInterface.release();
        }
    }

    return nullptr;
}

// Called at startup to conditionally set up ZMQ socket(s)
bool CZMQNotificationInterface::Initialize()
{
    int major = 0, minor = 0, patch = 0;
    zmq_version(&major, &minor, &patch);
    LogPrint(BCLog::ZMQ, "zmq: version %d.%d.%d\n", major, minor, patch);

    LogPrint(BCLog::ZMQ, "zmq: Initialize notification interface\n");
    assert(!pcontext);

    pcontext = zmq_ctx_new();

    if (!pcontext) {
        zmqError("Unable to initialize context");
        return false;
    }

    for (const auto& net : gArgs.GetArgs("-whitelistzmq")) {
        CSubNet subnet;
        LookupSubNet(net.c_str(), subnet);
        if (!subnet.IsValid())
            LogPrintf("Invalid netmask specified in -whitelistzmq: '%s'\n", net);
        else
            vWhitelistedRange.push_back(subnet);
    }

    if (vWhitelistedRange.size() > 0) {
        zapActive = false;
        threadZAP = std::thread(&TraceThread<std::function<void()> >, "zap", std::function<void()>(std::bind(&CZMQNotificationInterface::ThreadZAP, this)));

        for (size_t nTries = 1000; nTries > 0; nTries--) {
            if (zapActive) {
                break;
            }
            UninterruptibleSleep(std::chrono::milliseconds{100});
        }
        if (!zapActive) {
            zmqError("Unable to start zap thread");
            return false;
        }
    }

    for (auto& notifier : notifiers) {
        if (notifier->Initialize(pcontext)) {
            LogPrint(BCLog::ZMQ, "zmq: Notifier %s ready (address = %s)\n", notifier->GetType(), notifier->GetAddress());
        } else {
            LogPrint(BCLog::ZMQ, "zmq: Notifier %s failed (address = %s)\n", notifier->GetType(), notifier->GetAddress());
            return false;
        }
    }

    return true;
}

// Called during shutdown sequence
void CZMQNotificationInterface::Shutdown()
{
    LogPrint(BCLog::ZMQ, "zmq: Shutdown notification interface\n");

    if (threadZAP.joinable())
    {
        zapActive = false;
        threadZAP.join();
    };

    if (pcontext)
    {
        for (auto& notifier : notifiers) {
            LogPrint(BCLog::ZMQ, "zmq: Shutdown notifier %s at %s\n", notifier->GetType(), notifier->GetAddress());
            notifier->Shutdown();
        }
        zmq_ctx_term(pcontext);

        pcontext = nullptr;
    }
}

namespace {

template <typename Function>
void TryForEachAndRemoveFailed(std::list<std::unique_ptr<CZMQAbstractNotifier>>& notifiers, const Function& func)
{
    for (auto i = notifiers.begin(); i != notifiers.end(); ) {
        CZMQAbstractNotifier* notifier = i->get();
        if (func(notifier)) {
            ++i;
        } else {
            notifier->Shutdown();
            i = notifiers.erase(i);
        }
    }
}

} // anonymous namespace

void CZMQNotificationInterface::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
{
    if (fInitialDownload || pindexNew == pindexFork) // In IBD or blocks were disconnected without any new ones
        return;

    TryForEachAndRemoveFailed(notifiers, [pindexNew](CZMQAbstractNotifier* notifier) {
        return notifier->NotifyBlock(pindexNew);
    });
}

void CZMQNotificationInterface::TransactionAddedToMempool(const CTransactionRef& ptx, uint64_t mempool_sequence)
{
    const CTransaction& tx = *ptx;

    TryForEachAndRemoveFailed(notifiers, [&tx, mempool_sequence](CZMQAbstractNotifier* notifier) {
        return notifier->NotifyTransaction(tx) && notifier->NotifyTransactionAcceptance(tx, mempool_sequence);
    });
}

void CZMQNotificationInterface::TransactionRemovedFromMempool(const CTransactionRef& ptx, MemPoolRemovalReason reason, uint64_t mempool_sequence)
{
    // Called for all non-block inclusion reasons
    const CTransaction& tx = *ptx;

    TryForEachAndRemoveFailed(notifiers, [&tx, mempool_sequence](CZMQAbstractNotifier* notifier) {
        return notifier->NotifyTransactionRemoval(tx, mempool_sequence);
    });
}

void CZMQNotificationInterface::BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected)
{
    for (const CTransactionRef& ptx : pblock->vtx) {
        const CTransaction& tx = *ptx;
        TryForEachAndRemoveFailed(notifiers, [&tx](CZMQAbstractNotifier* notifier) {
            return notifier->NotifyTransaction(tx);
        });
    }

    // Next we notify BlockConnect listeners for *all* blocks
    TryForEachAndRemoveFailed(notifiers, [pindexConnected](CZMQAbstractNotifier* notifier) {
        return notifier->NotifyBlockConnect(pindexConnected);
    });
}

void CZMQNotificationInterface::BlockDisconnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexDisconnected)
{
    for (const CTransactionRef& ptx : pblock->vtx) {
        const CTransaction& tx = *ptx;
        TryForEachAndRemoveFailed(notifiers, [&tx](CZMQAbstractNotifier* notifier) {
            return notifier->NotifyTransaction(tx);
        });
    }

    // Next we notify BlockDisconnect listeners for *all* blocks
    TryForEachAndRemoveFailed(notifiers, [pindexDisconnected](CZMQAbstractNotifier* notifier) {
        return notifier->NotifyBlockDisconnect(pindexDisconnected);
    });
}

void CZMQNotificationInterface::TransactionAddedToWallet(const std::string &sWalletName, const CTransactionRef& ptx)
{
    const CTransaction& tx = *ptx;

    TryForEachAndRemoveFailed(notifiers, [sWalletName, &tx](CZMQAbstractNotifier* notifier) {
        return notifier->NotifyTransaction(sWalletName, tx);
    });
}

void CZMQNotificationInterface::NewSecureMessage(const smsg::SecureMessage *psmsg, const uint160 &hash)
{
    TryForEachAndRemoveFailed(notifiers, [psmsg, &hash](CZMQAbstractNotifier* notifier) {
        return notifier->NotifySecureMessage(psmsg, hash);
    });
}

CZMQNotificationInterface* g_zmq_notification_interface = nullptr;
