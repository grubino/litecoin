// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "bitcoinrpc.h"

#include "ciere/json/value.hpp"

using namespace ciere::json;
using namespace std;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, value& out);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = pindexBest;
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}


value blockToJSON(const CBlock& block, const CBlockIndex* blockindex)
{

    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);

    array_t txs;

    BOOST_FOREACH(const CTransaction&tx, block.vtx)
        txs.push_back(tx.GetHash().GetHex());

    value result = object()
      ("hash", block.GetHash().GetHex())
      ("confirmations", (int)txGen.GetDepthInMainChain())
      ("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION))
      ("height", blockindex->nHeight)
      ("version", block.nVersion)
      ("merkleroot", block.hashMerkleRoot.GetHex())
      ("tx", txs)
      ("time", (boost::int64_t)block.GetBlockTime())
      ("nonce", (boost::uint64_t)block.nNonce)
      ("bits", HexBits(block.nBits))
      ("difficulty", GetDifficulty(blockindex))
      ;

    if (blockindex->pprev)
      result["previousblockhash"] = blockindex->pprev->GetBlockHash().GetHex();
    if (blockindex->pnext)
      result["nextblockhash"] = blockindex->pnext->GetBlockHash().GetHex();
    return result;
}


value getblockcount(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}

value getbestblockhash(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "Returns the hash of the best (tip) block in the longest block chain.");

    return hashBestChain.GetHex();
}

value getdifficulty(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

    return GetDifficulty();
}


value settxfee(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 1)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_as<double>() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nTransactionFee = nAmount;
    return true;
}

value getrawmempool(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    value a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}

value getblockhash(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_as<int>();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    return pblockindex->phashBlock->GetHex();
}

value getblock(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 2)
        throw runtime_error(
            "getblock <hash> [verbose=true]\n"
            "If verbose is false, returns a string that is serialized, hex-encoded data for block <hash>.\n"
            "If verbose is true, returns an value with information about block <hash>."
        );

    std::string strHash = params[0].get_as<std::string>();
    uint256 hash(strHash);

    bool fVerbose = true;
    if (params.length() > 1)
        fVerbose = params[1].get_as<bool>();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex);

    if (!fVerbose)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex);
}

value gettxoutsetinfo(const value& params, bool fHelp)
{
  if (fHelp || params.length() != 0) {
        throw runtime_error("gettxoutsetinfo\n"
			    "Returns statistics about the unspent transaction output set.");
  }

  value ret;
  
  CCoinsStats stats;
  if (pcoinsTip->GetStats(stats)) {
    ret = object()
      ("height", (boost::int64_t)stats.nHeight)
      ("bestblock", stats.hashBlock.GetHex())
      ("transactions", (boost::int64_t)stats.nTransactions)
      ("txouts", (boost::int64_t)stats.nTransactionOutputs)
      ("bytes_serialized", (boost::int64_t)stats.nSerializedSize)
      ("hash_serialized", stats.hashSerialized.GetHex())
      ("total_amount", ValueFromAmount(stats.nTotalAmount))
      ;
  }
  return ret;
}

value gettxout(const value& params, bool fHelp)
{
  if (fHelp || params.length() < 2 || params.length() > 3)
    throw runtime_error(
			"gettxout <txid> <n> [includemempool=true]\n"
			"Returns details about an unspent transaction output.");
  
  value ret;
  
  std::string strHash = params[0].get_as<std::string>();
  uint256 hash(strHash);
  int n = params[1].get_as<int>();
  bool fMempool = true;
  if (params.length() > 2)
    fMempool = params[2].get_as<bool>();
  
  CCoins coins;
  if (fMempool) {
    LOCK(mempool.cs);
    CCoinsViewMemPool view(*pcoinsTip, mempool);
    if (!view.GetCoins(hash, coins))
      return null_t();
    mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else {
        if (!pcoinsTip->GetCoins(hash, coins))
	  return null_t();
    }
    if (n<0 || (unsigned int)n>=coins.vout.size() || coins.vout[n].IsNull())
      return null_t();

    ret["bestblock"] = pcoinsTip->GetBestBlock()->GetBlockHash().GetHex();
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT) {
      ret["confirmations"] = 0; 
    } else {
      ret["confirmations"] = pcoinsTip->GetBestBlock()->nHeight - coins.nHeight + 1;
    }
    ret["value"] = ValueFromAmount(coins.vout[n].nValue);
    value o;
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o);
    ret["scriptPubKey"] = o;
    ret["version"] = coins.nVersion;
    ret["coinbase"] = coins.fCoinBase;

    return ret;
}

value verifychain(const value& params, bool fHelp) {
  if (fHelp or params.length() > 2) {
    throw runtime_error("verifychain [check level] [num blocks]\n"
			"Verifies blockchain database.");
  }

  unsigned int nCheckLevel = user_options["checklevel"].as<unsigned int>();
  unsigned int nCheckDepth = user_options["checkblocks"].as<unsigned int>();
  if (params.length() > 0) {
    nCheckLevel = params[0].get_as<int>();
  }
  if (params.length() > 1) {
    nCheckDepth = params[1].get_as<int>();
  }
  
  return VerifyDB(nCheckLevel, nCheckDepth);
}

