// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "net.h"
#include "init.h"
#include "wallet.h"
#include "bitcoinrpc.h"
#include "base58.h"
#include "db.h"

#include "ciere/json/value.hpp"

#include <boost/assign/list_of.hpp>


using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace ciere::json;

//
// Utilities: convert hex-encoded Values
// (throws error if not hex).
//
uint256 ParseHashV(const value& v, string strName)
{
    string strHex;
    if (v.type() == string_type)
        strHex = v.get_as<std::string>();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}
uint256 ParseHashO(const value& o, string strKey)
{
    return ParseHashV(o[strKey], strKey);
}
vector<unsigned char> ParseHexV(const value& v, string strName)
{
    string strHex;
    if (v.type() == string_type)
        strHex = v.get_as<std::string>();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}
vector<unsigned char> ParseHexO(const value& o, string strKey)
{
    return ParseHexV(o[strKey], strKey);
}

void ScriptPubKeyToJSON(const CScript& scriptPubKey, value& out)
{
  txnouttype type;
  vector<CTxDestination> addresses;
  int nRequired;
  
  out["asm"] = scriptPubKey.ToString();
  out["hex"] = HexStr(scriptPubKey.begin(), scriptPubKey.end());
  
  if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
    out["type"] = GetTxnOutputType(TX_NONSTANDARD);
    return;
  }
  
  out["reqSigs"] = nRequired;
  out["type"] = GetTxnOutputType(type);
  
  value a = ciere::json::array();
  BOOST_FOREACH(const CTxDestination& addr, addresses) {
    a.push_back(CBitcoinAddress(addr).ToString());
  }
  out["addresses"] = a;
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, value& entry) {
    entry["txid"] = tx.GetHash().GetHex();
    entry["version"] = tx.nVersion;
    entry["locktime"] = (boost::int64_t)tx.nLockTime;
    value vin;
    BOOST_FOREACH(const CTxIn& txin, tx.vin) {
        value in;
        if (tx.IsCoinBase()) {
	  in["coinbase"] = HexStr(txin.scriptSig.begin(), txin.scriptSig.end());
	} else {
            in["txid"] =  txin.prevout.hash.GetHex();
            in["vout"] =  (boost::int64_t)txin.prevout.n;
            value o;
            o["asm"] =  txin.scriptSig.ToString();
            o["hex"] =  HexStr(txin.scriptSig.begin(), txin.scriptSig.end());
            in["scriptSig"] =  o;
        }
        in["sequence"] =  (boost::int64_t)txin.nSequence;
        vin.push_back(in);
    }
    entry["vin"] =  vin;
    value vout;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        value out;
        out["value"] =  ValueFromAmount(txout.nValue);
        out["n"] =  (boost::int64_t)i;
        value o;
        ScriptPubKeyToJSON(txout.scriptPubKey, o);
        out["scriptPubKey"] =  o;
        vout.push_back(out);
    }
    entry["vout"] =  vout;

    if (hashBlock != 0) {
        entry["blockhash"] =  hashBlock.GetHex();
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (pindex->IsInMainChain()) {
                entry["confirmations"] =  1 + nBestHeight - pindex->nHeight;
                entry["time"] =  (boost::int64_t)pindex->nTime;
                entry["blocktime"] =  (boost::int64_t)pindex->nTime;
            }
            else {
                entry["confirmations"] =  0;
	    }
        }
    }
}

value getrawtransaction(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 2)
        throw runtime_error(
            "getrawtransaction <txid> [verbose=0]\n"
            "If verbose=0, returns a string that is\n"
            "serialized, hex-encoded data for <txid>.\n"
            "If verbose is non-zero, returns an Object\n"
            "with information about <txid>.");

    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.length() > 1)
        fVerbose = (params[1].get_as<int>() != 0);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    string strHex = HexStr(ssTx.begin(), ssTx.end());

    if (!fVerbose)
        return strHex;

    value result;
    result["hex"] =  strHex;
    TxToJSON(tx, hashBlock, result);
    return result;
}

value listunspent(const value& params, bool fHelp)
{
    if (fHelp || params.length() > 3)
        throw runtime_error(
            "listunspent [minconf=1] [maxconf=9999999]  [\"address\",...]\n"
            "Returns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filtered to only include txouts paid to specified addresses.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}");

    std::list<value_types> expected_types = list_of(int_type)(int_type)(array_type);
    RPCTypeCheck(params, expected_types);

    int nMinDepth = 1;
    if (params.length() > 0)
        nMinDepth = params[0].get_as<int>();

    int nMaxDepth = 9999999;
    if (params.length() > 1)
        nMaxDepth = params[1].get_as<int>();

    set<CBitcoinAddress> setAddress;
    if (params.length() > 2) {
      value inputs = params[2];
      BOOST_FOREACH(value& input, get<array_t>(inputs.get_ast())) {
	CBitcoinAddress address(input.get_as<std::string>());
	if (!address.IsValid())
	  throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Litecoin address: ")+input.get_as<std::string>());
	if (setAddress.count(address))
	  throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_as<std::string>());
	setAddress.insert(address);
      }
    }
    
    value results = ciere::json::array();
    vector<COutput> vecOutputs;
    assert(pwalletMain != NULL);
    pwalletMain->AvailableCoins(vecOutputs, false);
    BOOST_FOREACH(const COutput& out, vecOutputs) {
      if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
	continue;
      
      if (setAddress.size())
	{
	  CTxDestination address;
	  if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
	    continue;
	  
	  if (!setAddress.count(address))
	    continue;
	}
      
      int64 nValue = out.tx->vout[out.i].nValue;
      const CScript& pk = out.tx->vout[out.i].scriptPubKey;
      value entry;
      entry["txid"] = out.tx->GetHash().GetHex();
      entry["vout"] = out.i;
      CTxDestination address;
      if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address)) {
	entry["address"] =  CBitcoinAddress(address).ToString();
	if (pwalletMain->mapAddressBook.count(address)) {
	  entry["account"] =  pwalletMain->mapAddressBook[address];
	}
      }
      entry["scriptPubKey"] =  HexStr(pk.begin(), pk.end());
      if (pk.IsPayToScriptHash()) {
	CTxDestination address;
	if (ExtractDestination(pk, address)) {
	  const CScriptID& hash = boost::get<const CScriptID&>(address);
	  CScript redeemScript;
	  if (pwalletMain->GetCScript(hash, redeemScript)) {
	    entry["redeemScript"] =  HexStr(redeemScript.begin(), redeemScript.end());
	  }
	}
      }
      entry["amount"] = ValueFromAmount(nValue);
      entry["confirmations"] = out.nDepth;
      results.push_back(entry);
    }
    
    return results;
}

value createrawtransaction(const value& params, bool fHelp)
{
  if (fHelp || params.length() != 2)
    throw runtime_error(
			"createrawtransaction [{\"txid\":txid,\"vout\":n},...] {address:amount,...}\n"
			"Create a transaction spending given inputs\n"
			"(array of objects containing transaction id and output number),\n"
			"sending to given address(es).\n"
			"Returns hex-encoded raw transaction.\n"
			"Note that the transaction's inputs are not signed, and\n"
			"it is not stored in the wallet or transmitted to the network.");

  std::list<value_types> expected_types = list_of(array_type)(object_type);
  RPCTypeCheck(params, expected_types);
  
  value inputs = params[0];
  value sendTo = params[1];
  
  CTransaction rawTx;
  
  BOOST_FOREACH(const value& input, get<array_t>(inputs.get_ast())) {
    const value& o = input;
    
    uint256 txid = ParseHashO(o, "txid");
    
    const value& vout_v = o["vout"];
    if (vout_v.type() != int_type)
      throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
    int nOutput = vout_v.get_as<int>();
    if (nOutput < 0)
      throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");
    
    CTxIn in(COutPoint(txid, nOutput));
    rawTx.vin.push_back(in);
  }
  
  set<CBitcoinAddress> setAddress;
  BOOST_FOREACH(const object_t::value_type& s, get<object_t>(sendTo.get_ast())) {
    CBitcoinAddress address(s.first);
    if (!address.IsValid()) {
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Litecoin address: ")+s.first);
    }
    
    if (setAddress.count(address)) {
      throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+s.first);
    }
    setAddress.insert(address);
    
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address.Get());
    int64 nAmount = AmountFromValue(s.second);
    
    CTxOut out(nAmount, scriptPubKey);
    rawTx.vout.push_back(out);
  }
  
  CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
  ss << rawTx;
  return HexStr(ss.begin(), ss.end());
}

value decoderawtransaction(const value& params, bool fHelp)
{
  if (fHelp || params.length() != 1)
    throw runtime_error(
			"decoderawtransaction <hex string>\n"
			"Return a JSON object representing the serialized, hex-encoded transaction.");
  
  vector<unsigned char> txData(ParseHexV(params[0], "argument"));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  CTransaction tx;
  try {
    ssData >> tx;
  }
  catch (std::exception &e) {
    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
  }
  
  value result;
  TxToJSON(tx, 0, result);
  
  return result;
}

value signrawtransaction(const value& params, bool fHelp)
{
  if (fHelp || params.length() < 1 || params.length() > 4)
    throw runtime_error("signrawtransaction <hex string> [{\"txid\":txid,\"vout\":n,\"scriptPubKey\""
			":hex,\"redeemScript\":hex},...] [<privatekey1>,...] [sighashtype=\"ALL\"]\n"
			"Sign inputs for raw transaction (serialized, hex-encoded).\n"
			"Second optional argument (may be null) is an array of previous transaction outputs that\n"
			"this transaction depends on but may not yet be in the block chain.\n"
			"Third optional argument (may be null) is an array of base58-encoded private\n"
			"keys that, if given, will be the only keys used to sign the transaction.\n"
			"Fourth optional argument is a string that is one of six values; ALL, NONE, SINGLE or\n"
			"ALL|ANYONECANPAY, NONE|ANYONECANPAY, SINGLE|ANYONECANPAY.\n"
			"Returns json object with keys:\n"
			"  hex : raw transaction with signature(s) (hex-encoded string)\n"
			"  complete : 1 if transaction has a complete set of signature (0 if not)"
			+ HelpRequiringPassphrase());
  
  
  std::list<value_types> expected_types = list_of(string_type)(array_type)(array_type)(string_type);
  RPCTypeCheck(params, expected_types, true);
  
  vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  vector<CTransaction> txVariants;
  while (!ssData.empty())
    {
      try {
	CTransaction tx;
	ssData >> tx;
	txVariants.push_back(tx);
      }
      catch (std::exception &e) {
	throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
      }
    }
  
  if (txVariants.empty())
    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");
  
  // mergedTx will end up with all the signatures; it
  // starts as a clone of the rawtx:
  CTransaction mergedTx(txVariants[0]);
  bool fComplete = true;
  
  // Fetch previous transactions (inputs):
  CCoinsView viewDummy;
  CCoinsViewCache view(viewDummy);
  {
    LOCK(mempool.cs);
    CCoinsViewCache &viewChain = *pcoinsTip;
    CCoinsViewMemPool viewMempool(viewChain, mempool);
    view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view
    
    BOOST_FOREACH(const CTxIn& txin, mergedTx.vin) {
      const uint256& prevHash = txin.prevout.hash;
      CCoins coins;
      view.GetCoins(prevHash, coins); // this is certainly allowed to fail
    }
    
    view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
  }
  
  bool fGivenKeys = false;
  CBasicKeyStore tempKeystore;
  if (params.length() > 2 && params[2].type() != null_type) {
    fGivenKeys = true;
    value keys = params[2];
    BOOST_FOREACH(value k, get<array_t>(keys.get_ast())) {
      CBitcoinSecret vchSecret;
      bool fGood = vchSecret.SetString(k.get_as<std::string>());
      if (!fGood)
	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
      CKey key = vchSecret.GetKey();
      tempKeystore.AddKey(key);
    }
  } else {
    EnsureWalletIsUnlocked();
  }
  
  // Add previous txouts given in the RPC call:
  if (params.length() > 1 && params[1].type() != null_type) {
    value prevTxs = params[1];
    BOOST_FOREACH(value& p, get<array_t>(prevTxs.get_ast())) {
      if (p.type() != object_type) {
	throw JSONRPCError(RPC_DESERIALIZATION_ERROR
			   , "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");
      }
      
      value prevOut = p;
      
      std::map<std::string, value_types> expected_type_map = map_list_of
	("txid", string_type)
	("vout", int_type)
	("scriptPubKey", string_type)
	;
      RPCTypeCheck(prevOut, expected_type_map);
      
      uint256 txid = ParseHashO(prevOut, "txid");
      
      int nOut = prevOut["vout"].get_as<int>();
      if (nOut < 0)
	throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");
      
      vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
      CScript scriptPubKey(pkData.begin(), pkData.end());
      
      CCoins coins;
      if (view.GetCoins(txid, coins)) {
	if (coins.IsAvailable(nOut) && coins.vout[nOut].scriptPubKey != scriptPubKey) {
	  string err("Previous output scriptPubKey mismatch:\n");
	  err = err + coins.vout[nOut].scriptPubKey.ToString() + "\nvs:\n"+
	    scriptPubKey.ToString();
	  throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
	}
	// what todo if txid is known, but the actual output isn't?
      }
      if ((unsigned int)nOut >= coins.vout.size())
	coins.vout.resize(nOut+1);
      coins.vout[nOut].scriptPubKey = scriptPubKey;
      coins.vout[nOut].nValue = 0; // we don't know the actual output value
      view.SetCoins(txid, coins);
      
      // if redeemScript given and not using the local wallet (private keys
      // given), add redeemScript to the tempKeystore so it can be signed:
      if (fGivenKeys && scriptPubKey.IsPayToScriptHash()) {
	std::map<string, value_types> expected_type_map = map_list_of
	  ("txid", string_type)
	  ("vout", int_type)
	  ("scriptPubKey", string_type)
	  ("redeemScript",string_type)
	  ;
	RPCTypeCheck(prevOut, expected_type_map);
	value v = prevOut["redeemScript"];
	if (!(v == null_t())) {
	  vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
	  CScript redeemScript(rsData.begin(), rsData.end());
	  tempKeystore.AddCScript(redeemScript);
	}
      }
    }
  }
  
  const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);
  
  int nHashType = SIGHASH_ALL;
  if (params.length() > 3 && params[3].type() != null_type)
    {
      static map<string, int> mapSigHashValues =
	boost::assign::map_list_of
	(string("ALL"), int(SIGHASH_ALL))
	(string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
	(string("NONE"), int(SIGHASH_NONE))
	(string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
	(string("SINGLE"), int(SIGHASH_SINGLE))
	(string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
	;
      string strHashType = params[3].get_as<std::string>();
      if (mapSigHashValues.count(strHashType))
	nHashType = mapSigHashValues[strHashType];
      else
	throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }
  
  bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);
  
  // Sign what we can:
  for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
      CTxIn& txin = mergedTx.vin[i];
      CCoins coins;
      if (!view.GetCoins(txin.prevout.hash, coins) || !coins.IsAvailable(txin.prevout.n))
	{
	  fComplete = false;
	  continue;
	}
      const CScript& prevPubKey = coins.vout[txin.prevout.n].scriptPubKey;
      
      txin.scriptSig.clear();
      // Only sign SIGHASH_SINGLE if there's a corresponding output:
      if (!fHashSingle || (i < mergedTx.vout.size()))
	SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);
      
      // ... and merge in other signatures:
      BOOST_FOREACH(const CTransaction& txv, txVariants)
	{
	  txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
	}
      if (!VerifyScript(txin.scriptSig, prevPubKey, mergedTx, i, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC, 0))
	fComplete = false;
    }
  
  CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
  ssTx << mergedTx;
  value result = object()
    ("hex", HexStr(ssTx.begin(), ssTx.end()))
    ("complete", fComplete)
    ;
  
  return result;
}

value sendrawtransaction(const value& params, bool fHelp) {
  if (fHelp || params.length() < 1 || params.length() > 1)
    throw runtime_error(
			"sendrawtransaction <hex string>\n"
			"Submits raw transaction (serialized, hex-encoded) to local node and network.");
  
  // parse hex string from parameter
  vector<unsigned char> txData(ParseHexV(params[0], "parameter"));
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  CTransaction tx;
  
  // deserialize binary data stream
  try {
    ssData >> tx;
  }
  catch (std::exception &e) {
    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
  }
  uint256 hashTx = tx.GetHash();
  
  bool fHave = false;
  CCoinsViewCache &view = *pcoinsTip;
  CCoins existingCoins;
  {
    fHave = view.GetCoins(hashTx, existingCoins);
    if (!fHave) {
      // push to local node
      CValidationState state;
      if (!tx.AcceptToMemoryPool(state, true, false))
	throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX rejected"); // TODO: report validation state
    }
  }
  if (fHave) {
    if (existingCoins.nHeight < 1000000000)
      throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "transaction already in block chain");
    // Not in block, but already in the memory pool; will drop
    // through to re-relay it.
  } else {
    SyncWithWallets(hashTx, tx, NULL, true);
  }
  RelayTransaction(tx, hashTx);
  
  return hashTx.GetHex();
}
