// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include "wallet.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "init.h"
#include "base58.h"

#include "ciere/json/value.hpp"
#include <boost/range/iterator_range.hpp>

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace ciere::json;

int64 nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

std::string HelpRequiringPassphrase()
{
    return pwalletMain && pwalletMain->IsCrypted()
        ? "\nrequires wallet passphrase to be set with walletpassphrase first"
        : "";
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
}

void WalletTxToJSON(const CWalletTx& wtx, value& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry["confirmations"] = confirms;
    if (wtx.IsCoinBase()) {
        entry["generated"] = true;
    }
    if (confirms) {
        entry["blockhash"] = wtx.hashBlock.GetHex();
        entry["blockindex"] = wtx.nIndex;
        entry["blocktime"] = (boost::int64_t)(mapBlockIndex[wtx.hashBlock]->nTime);
    }
    entry["txid"] = wtx.GetHash().GetHex();
    entry["time"] = (boost::int64_t)wtx.GetTxTime();
    entry["timereceived"] = (boost::int64_t)wtx.nTimeReceived;
    BOOST_FOREACH(const PAIRTYPE(string,string)& item, wtx.mapValue) {
      entry[item.first] = item.second;
    }
}

string AccountFromValue(const value& value)
{
    string strAccount = value.get_as<std::string>();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

value getinfo(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    value obj = object()
      ("version",       (int)CLIENT_VERSION)
      ("protocolversion",(int)PROTOCOL_VERSION)
      ("blocks",        (int)nBestHeight)
      ("timeoffset",    (boost::int64_t)GetTimeOffset())
      ("connections",   (int)vNodes.size())
      ("proxy",         (proxy.first.IsValid() ? proxy.first.ToStringIPPort() : string()))
      ("difficulty",    (double)GetDifficulty())
      ("testnet",       user_options.count("testnet") and user_options["testnet"].as<bool>())
      ("paytxfee",      ValueFromAmount(nTransactionFee))
      ("mininput",      ValueFromAmount(nMinimumInputValue))
      ("errors",        GetWarnings("statusbar"))
      ;
    if (pwalletMain) {
      obj["walletversion"] = pwalletMain->GetVersion();
      obj["balance"] = ValueFromAmount(pwalletMain->GetBalance());
    }
    if (pwalletMain) {
      obj["keypoololdest"] = (boost::int64_t)pwalletMain->GetOldestKeyPoolTime();
      obj["keypoolsize"] = (int)pwalletMain->GetKeyPoolSize();
    }
    if (pwalletMain && pwalletMain->IsCrypted()) {
      obj["unlocked_until"] = (boost::int64_t)nWalletUnlockTime;
    }
    return obj;
}



value getnewaddress(const value& params, bool fHelp)
{
    if (fHelp || params.length() > 1)
        throw runtime_error(
            "getnewaddress [account]\n"
            "Returns a new Litecoin address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.length() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBookName(keyID, strAccount);

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(string strAccount, bool bForceNew=false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid())
    {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
             it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid();
             ++it)
        {
            const CWalletTx& wtx = (*it).second;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed)
    {
        if (!pwalletMain->GetKeyFromPool(account.vchPubKey, false))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        pwalletMain->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey.GetID());
}

value getaccountaddress(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 1)
        throw runtime_error(
            "getaccountaddress <account>\n"
            "Returns the current Litecoin address for receiving payments to this account.");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    value ret;

    ret = GetAccountAddress(strAccount).ToString();

    return ret;
}



value setaccount(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 2)
        throw runtime_error(
            "setaccount <litecoinaddress> <account>\n"
            "Sets the account associated with the given address.");

    CBitcoinAddress address(params[0].get_as<std::string>());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address");


    string strAccount;
    if (params.length() > 1)
        strAccount = AccountFromValue(params[1]);

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (pwalletMain->mapAddressBook.count(address.Get()))
    {
        string strOldAccount = pwalletMain->mapAddressBook[address.Get()];
        if (address == GetAccountAddress(strOldAccount))
            GetAccountAddress(strOldAccount, true);
    }

    pwalletMain->SetAddressBookName(address.Get(), strAccount);

    return null_t();
}


value getaccount(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 1)
        throw runtime_error(
            "getaccount <litecoinaddress>\n"
            "Returns the account associated with the given address.");

    CBitcoinAddress address(params[0].get_as<std::string>());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address");

    string strAccount;
    map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
        strAccount = (*mi).second;
    return strAccount;
}


value getaddressesbyaccount(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 1)
        throw runtime_error(
            "getaddressesbyaccount <account>\n"
            "Returns the list of addresses for the given account.");

    string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    value ret;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}


value setmininput(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 1)
        throw runtime_error(
            "setmininput <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_as<double>() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nMinimumInputValue = nAmount;
    return true;
}


value sendtoaddress(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 2 || params.length() > 4)
        throw runtime_error(
            "sendtoaddress <litecoinaddress> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001"
            + HelpRequiringPassphrase());

    CBitcoinAddress address(params[0].get_as<std::string>());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address");

    // Amount
    int64 nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (params.length() > 2 && params[2].type() != null_type && !params[2].get_as<std::string>().empty())
        wtx.mapValue["comment"] = params[2].get_as<std::string>();
    if (params.length() > 3 && params[3].type() != null_type && !params[3].get_as<std::string>().empty())
        wtx.mapValue["to"]      = params[3].get_as<std::string>();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

value listaddressgroupings(const value& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listaddressgroupings\n"
            "Lists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions");

    value jsonGroupings;
    map<CTxDestination, int64> balances = pwalletMain->GetAddressBalances();
    BOOST_FOREACH(set<CTxDestination> grouping, pwalletMain->GetAddressGroupings())
    {
        value jsonGrouping;
        BOOST_FOREACH(CTxDestination address, grouping)
        {
            value addressInfo;
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                LOCK(pwalletMain->cs_wallet);
                if (pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwalletMain->mapAddressBook.end())
                    addressInfo.push_back(pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get())->second);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

value signmessage(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 2)
        throw runtime_error(
            "signmessage <litecoinaddress> <message>\n"
            "Sign a message with the private key of an address");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_as<std::string>();
    string strMessage = params[1].get_as<std::string>();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

value verifymessage(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 3)
        throw runtime_error(
            "verifymessage <litecoinaddress> <signature> <message>\n"
            "Verify a signed message");

    string strAddress  = params[0].get_as<std::string>();
    string strSign     = params[1].get_as<std::string>();
    string strMessage  = params[2].get_as<std::string>();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}


value getreceivedbyaddress(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 2)
        throw runtime_error(
            "getreceivedbyaddress <litecoinaddress> [minconf=1]\n"
            "Returns the total amount received by <litecoinaddress> in transactions with at least [minconf] confirmations.");

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_as<std::string>());
    CScript scriptPubKey;
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address");
    scriptPubKey.SetDestination(address.Get());
    if (!IsMine(*pwalletMain,scriptPubKey))
        return (double)0.0;

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.length() > 1)
        nMinDepth = params[1].get_as<int>();

    // Tally
    int64 nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


void GetAccountAddresses(string strAccount, set<CTxDestination>& setAddress)
{
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            setAddress.insert(address);
    }
}

value getreceivedbyaccount(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 2)
        throw runtime_error(
            "getreceivedbyaccount <account> [minconf=1]\n"
            "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.length() > 1)
        nMinDepth = params[1].get_as<int>();

    // Get the set of pub keys assigned to account
    string strAccount = AccountFromValue(params[0]);
    set<CTxDestination> setAddress;
    GetAccountAddresses(strAccount, setAddress);

    // Tally
    int64 nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwalletMain, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}


int64 GetAccountBalance(CWalletDB& walletdb, const string& strAccount, int nMinDepth)
{
    int64 nBalance = 0;

    // Tally wallet transactions
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (!wtx.IsFinal())
            continue;

        int64 nReceived, nSent, nFee;
        wtx.GetAccountAmounts(strAccount, nReceived, nSent, nFee);

        if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth)
            nBalance += nReceived;
        nBalance -= nSent + nFee;
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

int64 GetAccountBalance(const string& strAccount, int nMinDepth)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth);
}


value getbalance(const value& params, bool fHelp)
{
    if (fHelp || params.length() > 2)
        throw runtime_error(
            "getbalance [account] [minconf=1]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.");

    if (params.length() == 0)
        return  ValueFromAmount(pwalletMain->GetBalance());

    int nMinDepth = 1;
    if (params.length() > 1)
        nMinDepth = params[1].get_as<int>();

    if (params[0].get_as<std::string>() == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' 0 should return the same number
        int64 nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!wtx.IsConfirmed())
                continue;

            int64 allFee;
            string strSentAccount;
            list<pair<CTxDestination, int64> > listReceived;
            list<pair<CTxDestination, int64> > listSent;
            wtx.GetAmounts(listReceived, listSent, allFee, strSentAccount);
            if (wtx.GetDepthInMainChain() >= nMinDepth)
            {
                BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
                    nBalance += r.second;
            }
            BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listSent)
                nBalance -= r.second;
            nBalance -= allFee;
        }
        return  ValueFromAmount(nBalance);
    }

    string strAccount = AccountFromValue(params[0]);

    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);

    return ValueFromAmount(nBalance);
}


value movecmd(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 3 || params.length() > 5)
        throw runtime_error(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    int64 nAmount = AmountFromValue(params[2]);
    if (params.length() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_as<int>();
    string strComment;
    if (params.length() > 4)
        strComment = params[4].get_as<std::string>();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    if (!walletdb.TxnBegin())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    int64 nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    walletdb.WriteAccountingEntry(debit);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    walletdb.WriteAccountingEntry(credit);

    if (!walletdb.TxnCommit())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true;
}


value sendfrom(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 3 || params.length() > 6)
        throw runtime_error(
            "sendfrom <fromaccount> <tolitecoinaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001"
            + HelpRequiringPassphrase());

    string strAccount = AccountFromValue(params[0]);
    CBitcoinAddress address(params[1].get_as<std::string>());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Litecoin address");
    int64 nAmount = AmountFromValue(params[2]);
    int nMinDepth = 1;
    if (params.length() > 3)
        nMinDepth = params[3].get_as<int>();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.length() > 4 && params[4].type() != null_type && !params[4].get_as<std::string>().empty())
        wtx.mapValue["comment"] = params[4].get_as<std::string>();
    if (params.length() > 5 && params[5].type() != null_type && !params[5].get_as<std::string>().empty())
        wtx.mapValue["to"]      = params[5].get_as<std::string>();

    EnsureWalletIsUnlocked();

    // Check funds
    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}


value sendmany(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 2 || params.length() > 4)
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers"
            + HelpRequiringPassphrase());

    string strAccount = AccountFromValue(params[0]);
    value sendTo = params[1];
    int nMinDepth = 1;
    if (params.length() > 2) {
      nMinDepth = params[2].get_as<int>();
    }

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.length() > 3 && params[3].type() != null_type && !params[3].get_as<std::string>().empty())
        wtx.mapValue["comment"] = params[3].get_as<std::string>();

    set<CBitcoinAddress> setAddress;
    vector<pair<CScript, int64> > vecSend;

    int64 totalAmount = 0;
    BOOST_FOREACH(const value::member& s
		  , make_iterator_range(sendTo.begin_object()
					, sendTo.end_object())) {
      CBitcoinAddress address(s.name());
      if (!address.IsValid()) {
	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Litecoin address: ")+s.name());
      }

      if (setAddress.count(address)) {
	throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+s.name());
      }
      setAddress.insert(address);

      CScript scriptPubKey;
      scriptPubKey.SetDestination(address.Get());
      int64 nAmount = AmountFromValue(s.value());
      totalAmount += nAmount;

      vecSend.push_back(make_pair(scriptPubKey, nAmount));
    }

    EnsureWalletIsUnlocked();

    // Check funds
    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);
    if (totalAmount > nBalance) {
      throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");
    }

    // Send
    CReserveKey keyChange(pwalletMain);
    int64 nFeeRequired = 0;
    string strFailReason;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, strFailReason);
    if (!fCreated) {
      throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    }
    if (!pwalletMain->CommitTransaction(wtx, keyChange)) {
      throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");
    }

    return wtx.GetHash().GetHex();
}

//
// Used by addmultisigaddress / createmultisig:
//
static CScript _createmultisig(const value& params)
{
    int nRequired = params[0].get_as<int>();
    const value& keys = params[1];

    // Gather public keys
    if (nRequired < 1) {
      throw runtime_error("a multisignature address must require at least one key to redeem");
    }
    if ((int)keys.length() < nRequired) {
      throw runtime_error(strprintf("not enough keys supplied "
				    "(got %"PRIszu" keys, but need at least %d to redeem)"
				    , keys.length()
				    , nRequired));
    }
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.length());
    for (unsigned int i = 0; i < keys.length(); i++)
    {
        const std::string& ks = keys[i].get_as<std::string>();

        // Case 1: Litecoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (pwalletMain && address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks.c_str()));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks.c_str()));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }
    CScript result;
    result.SetMultisig(nRequired, pubkeys);
    return result;
}

value addmultisigaddress(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 2 || params.length() > 3)
    {
        string msg = "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a Litecoin address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    string strAccount;
    if (params.length() > 2)
        strAccount = AccountFromValue(params[2]);

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig(params);
    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return CBitcoinAddress(innerID).ToString();
}

value createmultisig(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 2 || params.length() > 2)
    {
        string msg = "createmultisig <nrequired> <'[\"key\",\"key\"]'>\n"
            "Creates a multi-signature address and returns a json object\n"
            "with keys:\n"
            "address : litecoin address\n"
            "redeemScript : hex-encoded redemption script";
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig(params);
    CScriptID innerID = inner.GetID();
    CBitcoinAddress address(innerID);

    value result = object()
      ("address", address.ToString())
      ("redeemScript", HexStr(inner.begin(), inner.end()))
      ;

    return result;
}


struct tallyitem
{
    int64 nAmount;
    int nConf;
    vector<uint256> txids;
    tallyitem() {
      nAmount = 0;
      nConf = std::numeric_limits<int>::max();
    }
};

value ListReceived(const value& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.length() > 0)
        nMinDepth = params[0].get_as<int>();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.length() > 1)
        fIncludeEmpty = params[1].get_as<bool>();

    // Tally
    map<CBitcoinAddress, tallyitem> mapTally;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;

        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address) || !IsMine(*pwalletMain, address))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
        }
    }

    // Reply
    value ret;
    map<string, tallyitem> mapAccountTally;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook) {
      const CBitcoinAddress& address = item.first;
      const string& strAccount = item.second;
      map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
      if (it == mapTally.end() && !fIncludeEmpty) {
	continue;
      }
      
      int64 nAmount = 0;
      int nConf = std::numeric_limits<int>::max();
      if (it != mapTally.end()) {
	nAmount = (*it).second.nAmount;
	nConf = (*it).second.nConf;
      }
      
      if (fByAccounts) {
	tallyitem& item = mapAccountTally[strAccount];
	item.nAmount += nAmount;
	item.nConf = min(item.nConf, nConf);
      } else {
	value obj = object()
	  ("address",       address.ToString())
	  ("account",       strAccount)
	  ("amount",        ValueFromAmount(nAmount))
	  ("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf))
	  ;
	value transactions;
	if (it != mapTally.end()) {
	  BOOST_FOREACH(const uint256& item, (*it).second.txids) {
	    transactions.push_back(item.GetHex());
	  }
	}
	obj["txids"] = transactions;
	ret.push_back(obj);
      }
    }
    
    if (fByAccounts) {
      for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it) {
	int64 nAmount = (*it).second.nAmount;
	int nConf = (*it).second.nConf;
	value obj = object()
	  ("account",       (*it).first)
	  ("amount",        ValueFromAmount(nAmount))
	  ("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf))
	  ;
	ret.push_back(obj);
      }
    }
    
    return ret;
}

value listreceivedbyaddress(const value& params, bool fHelp)
{
  if (fHelp || params.length() > 2) {
    throw runtime_error("listreceivedbyaddress [minconf=1] [includeempty=false]\n"
			"[minconf] is the minimum number of confirmations before payments are included.\n"
			"[includeempty] whether to include addresses that haven't received any payments.\n"
			"Returns an array of objects containing:\n"
			"  \"address\" : receiving address\n"
			"  \"account\" : the account of the receiving address\n"
			"  \"amount\" : total amount received by the address\n"
			"  \"confirmations\" : number of confirmations of the most recent transaction included\n"
			"  \"txids\" : list of transactions with outputs to the address\n");
  }
  
  return ListReceived(params, false);
}

value listreceivedbyaccount(const value& params, bool fHelp)
{
  if (fHelp || params.length() > 2)
    throw runtime_error(
			"listreceivedbyaccount [minconf=1] [includeempty=false]\n"
			"[minconf] is the minimum number of confirmations before payments are included.\n"
			"[includeempty] whether to include accounts that haven't received any payments.\n"
			"Returns an array of objects containing:\n"
			"  \"account\" : the account of the receiving addresses\n"
			"  \"amount\" : total amount received by addresses with this account\n"
			"  \"confirmations\" : number of confirmations of the most recent transaction included");
  
  return ListReceived(params, true);
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, value& ret)
{
  int64 nFee;
  string strSentAccount;
  list<pair<CTxDestination, int64> > listReceived;
  list<pair<CTxDestination, int64> > listSent;
  
  wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);
  
  bool fAllAccounts = (strAccount == string("*"));
  
  // Sent
  if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount)) {
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& s, listSent) {
      value entry = object()
	("account", strSentAccount)
	("address", CBitcoinAddress(s.first).ToString())
	("category", "send")
	("amount", ValueFromAmount(-s.second))
	("fee", ValueFromAmount(-nFee))
	;
      if (fLong) {
	WalletTxToJSON(wtx, entry);
      }
      ret.push_back(entry);
    }
  }
  
  // Received
  if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth) {
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& r, listReceived) {
      string account;
      if (pwalletMain->mapAddressBook.count(r.first)) {
	account = pwalletMain->mapAddressBook[r.first];
      }
      if (fAllAccounts || (account == strAccount)) {
	value entry = object()
	  ("account", account)
	  ("address", CBitcoinAddress(r.first).ToString())
	  ;
	if (wtx.IsCoinBase()) {
	  if (wtx.GetDepthInMainChain() < 1) {
	    entry["category"] = "orphan";
	  } else if (wtx.GetBlocksToMaturity() > 0) {
	    entry["category"] = "immature";
	  } else {
	    entry["category"] = "generate";
	  }
	}
	else {
	  entry["category"] = "receive";
	}
	entry["amount"] = ValueFromAmount(r.second);
	if (fLong) {
	  WalletTxToJSON(wtx, entry);
	}
	ret.push_back(entry);
      }
    }
  }
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, value& ret)
{
  bool fAllAccounts = (strAccount == string("*"));
  
  if (fAllAccounts || acentry.strAccount == strAccount) {
    value entry = object()
      ("account", acentry.strAccount)
      ("category", "move")
      ("time", (boost::int64_t)acentry.nTime)
      ("amount", ValueFromAmount(acentry.nCreditDebit))
      ("otheraccount", acentry.strOtherAccount)
      ("comment", acentry.strComment)
      ;
    ret.push_back(entry);
  }
}

value listtransactions(const value& params, bool fHelp)
{
  if (fHelp || params.length() > 3)
    throw runtime_error(
			"listtransactions [account] [count=10] [from=0]\n"
			"Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");
  
  string strAccount = "*";
  if (params.length() > 0)
    strAccount = params[0].get_as<std::string>();
  int nCount = 10;
  if (params.length() > 1)
    nCount = params[1].get_as<int>();
  int nFrom = 0;
  if (params.length() > 2)
    nFrom = params[2].get_as<int>();
  
  if (nCount < 0)
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
  if (nFrom < 0)
    throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");
  
  value ret;
  
  std::list<CAccountingEntry> acentries;
  CWallet::TxItems txOrdered = pwalletMain->OrderedTxItems(acentries, strAccount);
  
  // iterate backwards until we have nCount items to return:
  for (CWallet::TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
    CWalletTx *const pwtx = (*it).second.first;
    if (pwtx != 0) {
      ListTransactions(*pwtx, strAccount, 0, true, ret);
    }
    CAccountingEntry *const pacentry = (*it).second.second;
    if (pacentry != 0) {
      AcentryToJSON(*pacentry, strAccount, ret);
    }
    if ((int)ret.length() >= (nCount+nFrom)) break;
  }
  // ret is newest to oldest
  
  if (nFrom > (int)ret.length()) {
    nFrom = ret.length();
  }
  if ((nFrom + nCount) > (int)ret.length()) {
    nCount = ret.length() - nFrom;
  }
  array_t::iterator first = get<array_t>(ret).begin();
  array_t::iterator last = get<array_t>(ret).begin();
  std::advance(first, nFrom);
  std::advance(last, nFrom+nCount);
  
  if (last != get<array_t>(ret).end()) {
    get<array_t>(ret).erase(last, get<array_t>(ret).end());
  }
  if (first != get<array_t>(ret).begin()) {
    get<array_t>(ret).erase(get<array_t>(ret).begin(), first);
  }
  
  std::reverse(first, last); // Return oldest to newest
  
  return ret;
}

value listaccounts(const value& params, bool fHelp)
{
  if (fHelp || params.length() > 1)
    throw runtime_error(
			"listaccounts [minconf=1]\n"
			"Returns value that has account names as keys, account balances as values.");
  
  int nMinDepth = 1;
  if (params.length() > 0) {
    nMinDepth = params[0].get_as<int>();
  }
  
  map<string, int64> mapAccountBalances;
  BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) {
    if (IsMine(*pwalletMain, entry.first)) // This address belongs to me
      mapAccountBalances[entry.second] = 0;
  }
  
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
      const CWalletTx& wtx = (*it).second;
      int64 nFee;
      string strSentAccount;
      list<pair<CTxDestination, int64> > listReceived;
      list<pair<CTxDestination, int64> > listSent;
      wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);
      mapAccountBalances[strSentAccount] -= nFee;
      BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& s, listSent)
	mapAccountBalances[strSentAccount] -= s.second;
      if (wtx.GetDepthInMainChain() >= nMinDepth)
        {
	  BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64)& r, listReceived)
	    if (pwalletMain->mapAddressBook.count(r.first))
	      mapAccountBalances[pwalletMain->mapAddressBook[r.first]] += r.second;
	    else
	      mapAccountBalances[""] += r.second;
        }
    }
  
  list<CAccountingEntry> acentries;
  CWalletDB(pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
  BOOST_FOREACH(const CAccountingEntry& entry, acentries)
    mapAccountBalances[entry.strAccount] += entry.nCreditDebit;
  
  value ret;
  BOOST_FOREACH(const PAIRTYPE(string, int64)& accountBalance, mapAccountBalances) {
    ret[accountBalance.first] = ValueFromAmount(accountBalance.second);
  }
  return ret;
}

value listsinceblock(const value& params, bool fHelp)
{
  if (fHelp) {
    throw runtime_error("listsinceblock [blockhash] [target-confirmations]\n"
			"Get all transactions in blocks since block [blockhash], or all transactions if omitted");
  }
  
  CBlockIndex *pindex = NULL;
  unsigned int target_confirms = 1;
  
  if (params.length() > 0)
    {
      uint256 blockId = 0;
      
      blockId.SetHex(params[0].get_as<std::string>());
      pindex = CBlockLocator(blockId).GetBlockIndex();
    }
  
  if (params.length() > 1) {
    target_confirms = params[1].get_as<unsigned int>();
    
    if (target_confirms < 1) {
      throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }
  }
  
  int depth = pindex ? (1 + nBestHeight - pindex->nHeight) : -1;
  
  value transactions;
  
  for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); it++)
    {
      CWalletTx tx = (*it).second;
      
      if (depth == -1 || tx.GetDepthInMainChain() < depth)
	ListTransactions(tx, "*", 0, true, transactions);
    }
  
  uint256 lastblock;
  
  if (target_confirms == 1)
    {
      lastblock = hashBestChain;
    }
  else
    {
      int target_height = pindexBest->nHeight + 1 - target_confirms;
      
      CBlockIndex *block;
      for (block = pindexBest;
	   block && block->nHeight > target_height;
	   block = block->pprev)  { }
      
      lastblock = block ? block->GetBlockHash() : 0;
    }
  
  value ret = object()
    ("transactions", transactions)
    ("lastblock", lastblock.GetHex())
    ;
  
  return ret;
}

value gettransaction(const value& params, bool fHelp)
{
  if (fHelp || params.length() != 1)
    throw runtime_error(
			"gettransaction <txid>\n"
			"Get detailed information about in-wallet transaction <txid>");
  
  uint256 hash;
  hash.SetHex(params[0].get_as<std::string>());
  
  value entry;
  if (!pwalletMain->mapWallet.count(hash))
    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
  const CWalletTx& wtx = pwalletMain->mapWallet[hash];
  
  int64 nCredit = wtx.GetCredit();
  int64 nDebit = wtx.GetDebit();
  int64 nNet = nCredit - nDebit;
  int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);
  
  entry["amount"] = ValueFromAmount(nNet - nFee);
  if (wtx.IsFromMe()) {
    entry["fee"] = ValueFromAmount(nFee);
  }
  
  WalletTxToJSON(wtx, entry);
  
  value details;
  ListTransactions(wtx, "*", 0, false, details);
  entry["details"] = details;
  
  return entry;
}


value backupwallet(const value& params, bool fHelp)
{
  if (fHelp || params.length() != 1)
    throw runtime_error(
			"backupwallet <destination>\n"
			"Safely copies wallet.dat to destination, which can be a directory or a path with filename.");
  
  string strDest = params[0].get_as<std::string>();
  if (!BackupWallet(*pwalletMain, strDest))
    throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
  
  return null_t();
}


value keypoolrefill(const value& params, bool fHelp)
{
  if (fHelp || params.length() > 0)
    throw runtime_error(
			"keypoolrefill\n"
			"Fills the keypool."
			+ HelpRequiringPassphrase());
  
  EnsureWalletIsUnlocked();
  
  pwalletMain->TopUpKeyPool();
  
  if (pwalletMain->GetKeyPoolSize() < user_options["keypool"].as<int>()) {
    throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
  }
  
  return null_t();
}


void ThreadTopUpKeyPool(void* parg)
{
  // Make this thread recognisable as the key-topping-up thread
  RenameThread("bitcoin-key-top");
  
  pwalletMain->TopUpKeyPool();
}

void ThreadCleanWalletPassphrase(void* parg)
{
  // Make this thread recognisable as the wallet relocking thread
  RenameThread("bitcoin-lock-wa");
  
  int64 nMyWakeTime = GetTimeMillis() + *((int64*)parg) * 1000;
  
  ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);
  
  if (nWalletUnlockTime == 0)
    {
      nWalletUnlockTime = nMyWakeTime;
      
      do
        {
	  if (nWalletUnlockTime==0)
	    break;
	  int64 nToSleep = nWalletUnlockTime - GetTimeMillis();
	  if (nToSleep <= 0)
	    break;
	  
	  LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
	  MilliSleep(nToSleep);
	  ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);
	  
        } while(1);
      
      if (nWalletUnlockTime)
        {
	  nWalletUnlockTime = 0;
	  pwalletMain->Lock();
        }
    }
  else
    {
      if (nWalletUnlockTime < nMyWakeTime)
	nWalletUnlockTime = nMyWakeTime;
    }
  
  LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
  
  delete (int64*)parg;
}

value walletpassphrase(const value& params, bool fHelp)
{
  if (pwalletMain->IsCrypted() && (fHelp || params.length() != 2))
    throw runtime_error(
			"walletpassphrase <passphrase> <timeout>\n"
			"Stores the wallet decryption key in memory for <timeout> seconds.");
  if (fHelp)
    return true;
  if (!pwalletMain->IsCrypted())
    throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
  
  if (!pwalletMain->IsLocked())
    throw JSONRPCError(RPC_WALLET_ALREADY_UNLOCKED, "Error: Wallet is already unlocked.");
  
  // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
  SecureString strWalletPass;
  strWalletPass.reserve(100);
  // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
  // Alternately, find a way to make params[0] mlock()'d to begin with.
  strWalletPass = params[0].get_as<std::string>().c_str();
  
  if (strWalletPass.length() > 0)
    {
      if (!pwalletMain->Unlock(strWalletPass))
	throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
  else
    throw runtime_error(
			"walletpassphrase <passphrase> <timeout>\n"
			"Stores the wallet decryption key in memory for <timeout> seconds.");
  
  NewThread(ThreadTopUpKeyPool, NULL);
  int64* pnSleepTime = new int64(params[1].get_as<int>());
  NewThread(ThreadCleanWalletPassphrase, pnSleepTime);
  
  return null_t();
}


value walletpassphrasechange(const value& params, bool fHelp)
{
  if (pwalletMain->IsCrypted() && (fHelp || params.length() != 2))
    throw runtime_error(
			"walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
			"Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
  if (fHelp)
    return true;
  if (!pwalletMain->IsCrypted())
    throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
  
  // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
  // Alternately, find a way to make params[0] mlock()'d to begin with.
  SecureString strOldWalletPass;
  strOldWalletPass.reserve(100);
  strOldWalletPass = params[0].get_as<std::string>().c_str();
  
  SecureString strNewWalletPass;
  strNewWalletPass.reserve(100);
  strNewWalletPass = params[1].get_as<std::string>().c_str();
  
  if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
    throw runtime_error(
			"walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
			"Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
  
  if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
    throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
  
  return null_t();
}


value walletlock(const value& params, bool fHelp)
{
  if (pwalletMain->IsCrypted() && (fHelp || params.length() != 0))
    throw runtime_error(
			"walletlock\n"
			"Removes the wallet encryption key from memory, locking the wallet.\n"
			"After calling this method, you will need to call walletpassphrase again\n"
			"before being able to call any methods which require the wallet to be unlocked.");
  if (fHelp)
    return true;
  if (!pwalletMain->IsCrypted())
    throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
  
  {
    LOCK(cs_nWalletUnlockTime);
    pwalletMain->Lock();
    nWalletUnlockTime = 0;
  }
  
  return null_t();
}


value encryptwallet(const value& params, bool fHelp)
{
  if (!pwalletMain->IsCrypted() && (fHelp || params.length() != 1))
    throw runtime_error(
			"encryptwallet <passphrase>\n"
			"Encrypts the wallet with <passphrase>.");
  if (fHelp)
    return true;
  if (pwalletMain->IsCrypted())
    throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
  
  // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
  // Alternately, find a way to make params[0] mlock()'d to begin with.
  SecureString strWalletPass;
  strWalletPass.reserve(100);
  strWalletPass = params[0].get_as<std::string>().c_str();
  
  if (strWalletPass.length() < 1)
    throw runtime_error(
			"encryptwallet <passphrase>\n"
			"Encrypts the wallet with <passphrase>.");
  
  if (!pwalletMain->EncryptWallet(strWalletPass))
    throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");
  
  // BDB seems to have a bad habit of writing old data into
  // slack space in .dat files; that is bad if the old data is
  // unencrypted private keys. So:
  StartShutdown();
  return "wallet encrypted; Litecoin server stopping, restart to run with encrypted wallet. The keypool has been flushed, you need to make a new backup.";
}

class DescribeAddressVisitor : public boost::static_visitor<value> {
public:
  value operator()(const CNoDestination &dest) const { return value(); }
  
  value operator()(const CKeyID &keyID) const {
    CPubKey vchPubKey;
    pwalletMain->GetPubKey(keyID, vchPubKey);
    value obj = object()
      ("isscript", false)
      ("pubkey", HexStr(vchPubKey))
      ("iscompressed", vchPubKey.IsCompressed())
      ;
    return obj;
  }
  
  value operator()(const CScriptID &scriptID) const {
    value obj = object()("isscript", true);
    CScript subscript;
    pwalletMain->GetCScript(scriptID, subscript);
    std::vector<CTxDestination> addresses;
    txnouttype whichType;
    int nRequired;
    ExtractDestinations(subscript, whichType, addresses, nRequired);
    obj["script"] = GetTxnOutputType(whichType);
    value a;
    BOOST_FOREACH(const CTxDestination& addr, addresses) {
      a.push_back(CBitcoinAddress(addr).ToString());
    }
    obj["addresses"] = a;
    if (whichType == TX_MULTISIG) {
      obj["sigsrequired"] = nRequired;
    }
    return obj;
  }
};

value validateaddress(const value& params, bool fHelp) {
  if (fHelp || params.length() != 1) {
    throw runtime_error("validateaddress <litecoinaddress>\n"
			"Return information about <litecoinaddress>.");
  }
  
  CBitcoinAddress address(params[0].get_as<std::string>());
  bool isValid = address.IsValid();
  
  value ret;
  ret["isvalid"] = isValid;
  if (isValid) {
    CTxDestination dest = address.Get();
    string currentAddress = address.ToString();
    bool fMine = pwalletMain ? IsMine(*pwalletMain, dest) : false;

    ret["address"] = currentAddress;
    ret["ismine"] = fMine;
    
    if (fMine) {
      value detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
      get<object_t>(ret.get_ast()).insert(get<object_t>(detail.get_ast()).begin()
					  , get<object_t>(detail.get_ast()).end());
    }
    if (pwalletMain && pwalletMain->mapAddressBook.count(dest)) {
      ret["account"] = pwalletMain->mapAddressBook[dest];
    }
  }
  return ret;
}

value lockunspent(const value& params, bool fHelp) {
  if (fHelp || params.length() < 1 || params.length() > 2) {
    throw runtime_error("lockunspent unlock? [array-of-values]\n"
            "Updates list of temporarily unspendable outputs.");
  }
  
  if (params.length() == 1) {
    std::list<value_types> expected_types = list_of(bool_type);
    RPCTypeCheck(params, expected_types);
  } else {
    std::list<value_types> expected_types = list_of(bool_type)(array_type);
    RPCTypeCheck(params, expected_types);
  }
  
  bool fUnlock = params[0].get_as<bool>();
  
  if (params.length() == 1) {
    if (fUnlock) {
      pwalletMain->UnlockAllCoins();
    }
    return true;
  }
  
  value outputs = params[1];
  BOOST_FOREACH(value& output
		, make_iterator_range(outputs.begin_array()
				      , outputs.end_array())) {
    if (output.type() != object_type) {
      throw JSONRPCError(-8, "Invalid parameter, expected object");
    }
    const value& o = output;

    std::map<std::string, value_types> expected_types = 
      map_list_of("txid", string_type)("vout", int_type);
    RPCTypeCheck(o, expected_types);
    
    string txid = o["txid"].get_as<std::string>();
    if (!IsHex(txid)) {
      throw JSONRPCError(-8, "Invalid parameter, expected hex txid");
    }
    
    int nOutput = o["vout"].get_as<int>();
    if (nOutput < 0) {
      throw JSONRPCError(-8, "Invalid parameter, vout must be positive");
    }
    
    COutPoint outpt(uint256(txid), nOutput);
    
    if (fUnlock) {
      pwalletMain->UnlockCoin(outpt);
    } else {
      pwalletMain->LockCoin(outpt);
    }
  }
  
  return true;
}

value listlockunspent(const value& params, bool fHelp) {
  if (fHelp || params.length() > 0) {
    throw runtime_error("listlockunspent\n"
			"Returns list of temporarily unspendable outputs.");
  }
  
  vector<COutPoint> vOutpts;
  pwalletMain->ListLockedCoins(vOutpts);
  
  value ret = ciere::json::array();
  
  BOOST_FOREACH(COutPoint &outpt, vOutpts) {
    value o = object()    
      ("txid", outpt.hash.GetHex())
      ("vout", (int)outpt.n);
    ret.push_back(o);
  }
  
  return ret;
}

