// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOINRPC_H_
#define _BITCOINRPC_H_ 1

#include <string>
#include <list>
#include <map>

class CBlockIndex;
class CReserveKey;

#include "ciere/json/io.hpp"
#include "ciere/json/value.hpp"

namespace json = ciere::json;

#include "util.h"

// HTTP status codes
enum HTTPStatusCode
  {
    HTTP_OK                    = 200,
    HTTP_BAD_REQUEST           = 400,
    HTTP_UNAUTHORIZED          = 401,
    HTTP_FORBIDDEN             = 403,
    HTTP_NOT_FOUND             = 404,
    HTTP_INTERNAL_SERVER_ERROR = 500,
  };

// Bitcoin RPC error codes
enum RPCErrorCode
  {
    // Standard JSON-RPC 2.0 errors
    RPC_INVALID_REQUEST  = -32600,
    RPC_METHOD_NOT_FOUND = -32601,
    RPC_INVALID_PARAMS   = -32602,
    RPC_INTERNAL_ERROR   = -32603,
    RPC_PARSE_ERROR      = -32700,
    
    // General application defined errors
    RPC_MISC_ERROR                  = -1,  // std::exception thrown in command handling
    RPC_FORBIDDEN_BY_SAFE_MODE      = -2,  // Server is in safe mode, and command is not allowed in safe mode
    RPC_TYPE_ERROR                  = -3,  // Unexpected type was passed as parameter
    RPC_INVALID_ADDRESS_OR_KEY      = -5,  // Invalid address or key
    RPC_OUT_OF_MEMORY               = -7,  // Ran out of memory during operation
    RPC_INVALID_PARAMETER           = -8,  // Invalid, missing or duplicate parameter
    RPC_DATABASE_ERROR              = -20, // Database error
    RPC_DESERIALIZATION_ERROR       = -22, // Error parsing or validating structure in raw format

    // P2P client errors
    RPC_CLIENT_NOT_CONNECTED        = -9,  // Bitcoin is not connected
    RPC_CLIENT_IN_INITIAL_DOWNLOAD  = -10, // Still downloading initial blocks

    // Wallet errors
    RPC_WALLET_ERROR                = -4,  // Unspecified problem with wallet (key not found etc.)
    RPC_WALLET_INSUFFICIENT_FUNDS   = -6,  // Not enough funds in wallet or account
    RPC_WALLET_INVALID_ACCOUNT_NAME = -11, // Invalid account name
    RPC_WALLET_KEYPOOL_RAN_OUT      = -12, // Keypool ran out, call keypoolrefill first
    RPC_WALLET_UNLOCK_NEEDED        = -13, // Enter the wallet passphrase with walletpassphrase first
    RPC_WALLET_PASSPHRASE_INCORRECT = -14, // The wallet passphrase entered was incorrect
    RPC_WALLET_WRONG_ENC_STATE      = -15, // Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    RPC_WALLET_ENCRYPTION_FAILED    = -16, // Failed to encrypt the wallet
    RPC_WALLET_ALREADY_UNLOCKED     = -17, // Wallet is already unlocked
};

json::value JSONRPCError(int code, const std::string& message);

void StartRPCThreads();
void StopRPCThreads();
int CommandLineRPC(int argc, char *argv[]);

/** Convert parameter values for RPC call from strings to command-specific JSON objects. */
json::value RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams);

/*
  Type-check arguments; throws JSONRPCError if wrong type given. Does not check that
  the right number of arguments are passed, just that any passed are the correct type.
  Use like:  RPCTypeCheck(params, boost::assign::list_of(str_type)(int_type)(obj_type));
*/
void RPCTypeCheck(const json::value& params
		  , const std::list<json::value_types>& typesExpected
		  , bool fAllowNull = false);
/*
  Check for expected keys/value types in an Object.
  Use like: RPCTypeCheck(object, boost::assign::map_list_of("name", str_type)("value", int_type));
*/
void RPCTypeCheck(const json::value& o
		  , const std::map<std::string, json::value_types>& typesExpected
		  , bool fAllowNull=false);

typedef json::value(*rpcfn_type)(const json::value& params, bool fHelp);

class CRPCCommand
{
public:
    std::string name;
    rpcfn_type actor;
    bool okSafeMode;
    bool threadSafe;
    bool reqWallet;
};

/**
 * Bitcoin RPC command dispatcher.
 */
class CRPCTable
{
private:
    std::map<std::string, const CRPCCommand*> mapCommands;
public:
    CRPCTable();
    const CRPCCommand* operator[](std::string name) const;
    std::string help(std::string name) const;

    /**
     * Execute a method.
     * @param method   Method to execute
     * @param params   Array of arguments (JSON objects)
     * @returns Result of the call.
     * @throws an exception (json::value) when an error happens.
     */
    json::value execute(const std::string &method, const json::value &params) const;
};

extern const CRPCTable tableRPC;

extern void InitRPCMining();
extern void ShutdownRPCMining();

extern int64 nWalletUnlockTime;
extern int64 AmountFromValue(const json::value& value);
extern json::value ValueFromAmount(int64 amount);
extern double GetDifficulty(const CBlockIndex* blockindex = NULL);
extern std::string HexBits(unsigned int nBits);
extern std::string HelpRequiringPassphrase();
extern void EnsureWalletIsUnlocked();

extern json::value getconnectioncount(const json::value& params, bool fHelp); // in rpcnet.cpp
extern json::value getpeerinfo(const json::value& params, bool fHelp);
extern json::value addnode(const json::value& params, bool fHelp);
extern json::value getaddednodeinfo(const json::value& params, bool fHelp);
extern json::value dumpprivkey(const json::value& params, bool fHelp); // in rpcdump.cpp
extern json::value importprivkey(const json::value& params, bool fHelp);

extern json::value getgenerate(const json::value& params, bool fHelp); // in rpcmining.cpp
extern json::value setgenerate(const json::value& params, bool fHelp);
extern json::value getnetworkhashps(const json::value& params, bool fHelp);
extern json::value gethashespersec(const json::value& params, bool fHelp);
extern json::value getmininginfo(const json::value& params, bool fHelp);
extern json::value getworkex(const json::value& params, bool fHelp);
extern json::value getwork(const json::value& params, bool fHelp);
extern json::value getblocktemplate(const json::value& params, bool fHelp);
extern json::value submitblock(const json::value& params, bool fHelp);

extern json::value getnewaddress(const json::value& params, bool fHelp); // in rpcwallet.cpp
extern json::value getaccountaddress(const json::value& params, bool fHelp);
extern json::value setaccount(const json::value& params, bool fHelp);
extern json::value getaccount(const json::value& params, bool fHelp);
extern json::value getaddressesbyaccount(const json::value& params, bool fHelp);
extern json::value sendtoaddress(const json::value& params, bool fHelp);
extern json::value signmessage(const json::value& params, bool fHelp);
extern json::value verifymessage(const json::value& params, bool fHelp);
extern json::value getreceivedbyaddress(const json::value& params, bool fHelp);
extern json::value getreceivedbyaccount(const json::value& params, bool fHelp);
extern json::value getbalance(const json::value& params, bool fHelp);
extern json::value movecmd(const json::value& params, bool fHelp);
extern json::value sendfrom(const json::value& params, bool fHelp);
extern json::value sendmany(const json::value& params, bool fHelp);
extern json::value addmultisigaddress(const json::value& params, bool fHelp);
extern json::value createmultisig(const json::value& params, bool fHelp);
extern json::value listreceivedbyaddress(const json::value& params, bool fHelp);
extern json::value listreceivedbyaccount(const json::value& params, bool fHelp);
extern json::value listtransactions(const json::value& params, bool fHelp);
extern json::value listaddressgroupings(const json::value& params, bool fHelp);
extern json::value listaccounts(const json::value& params, bool fHelp);
extern json::value listsinceblock(const json::value& params, bool fHelp);
extern json::value gettransaction(const json::value& params, bool fHelp);
extern json::value backupwallet(const json::value& params, bool fHelp);
extern json::value keypoolrefill(const json::value& params, bool fHelp);
extern json::value walletpassphrase(const json::value& params, bool fHelp);
extern json::value walletpassphrasechange(const json::value& params, bool fHelp);
extern json::value walletlock(const json::value& params, bool fHelp);
extern json::value encryptwallet(const json::value& params, bool fHelp);
extern json::value validateaddress(const json::value& params, bool fHelp);
extern json::value getinfo(const json::value& params, bool fHelp);

extern json::value getrawtransaction(const json::value& params, bool fHelp); // in rcprawtransaction.cpp
extern json::value listunspent(const json::value& params, bool fHelp);
extern json::value lockunspent(const json::value& params, bool fHelp);
extern json::value listlockunspent(const json::value& params, bool fHelp);
extern json::value createrawtransaction(const json::value& params, bool fHelp);
extern json::value decoderawtransaction(const json::value& params, bool fHelp);
extern json::value signrawtransaction(const json::value& params, bool fHelp);
extern json::value sendrawtransaction(const json::value& params, bool fHelp);

extern json::value getblockcount(const json::value& params, bool fHelp); // in rpcblockchain.cpp
extern json::value getbestblockhash(const json::value& params, bool fHelp);
extern json::value getdifficulty(const json::value& params, bool fHelp);
extern json::value settxfee(const json::value& params, bool fHelp);
extern json::value setmininput(const json::value& params, bool fHelp);
extern json::value getrawmempool(const json::value& params, bool fHelp);
extern json::value getblockhash(const json::value& params, bool fHelp);
extern json::value getblock(const json::value& params, bool fHelp);
extern json::value gettxoutsetinfo(const json::value& params, bool fHelp);
extern json::value gettxout(const json::value& params, bool fHelp);
extern json::value verifychain(const json::value& params, bool fHelp);

#endif
