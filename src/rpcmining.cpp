// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "db.h"
#include "init.h"
#include "bitcoinrpc.h"

#include "ciere/json/value.hpp"

#include <boost/program_options.hpp>

using namespace ciere::json;
using namespace std;

namespace po = boost::program_options;
namespace fs = boost::filesystem;

extern po::variables_map user_options;
extern po::options_description gen_opts;

// Return average network hashes per second based on the last 'lookup' blocks,
// or from the last difficulty change if 'lookup' is nonpositive.
// If 'height' is nonnegative, compute the estimate at the time when a given block was found.
value GetNetworkHashPS(int lookup, int height) {
    CBlockIndex *pb = pindexBest;

    if (height >= 0 && height < nBestHeight)
        pb = FindBlockByHeight(height);

    if (pb == NULL || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0)
        lookup = pb->nHeight % 2016 + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64 minTime = pb0->GetBlockTime();
    int64 maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64 time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64 timeDiff = maxTime - minTime;

    return (boost::int64_t)(workDiff.getdouble() / timeDiff);
}

value getnetworkhashps(const value& params, bool fHelp)
{
    if (fHelp || params.length() > 2)
        throw runtime_error(
            "getnetworkhashps [blocks] [height]\n"
            "Returns the estimated network hashes per second based on the last 120 blocks.\n"
            "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
            "Pass in [height] to estimate the network speed at the time when a certain block was found.");

    return GetNetworkHashPS(params.length() > 0 ? params[0].get_as<unsigned int>() : 120, params.length() > 1 ? params[1].get_as<unsigned int>() : -1);
}


// Key used by getwork/getblocktemplate miners.
// Allocated in InitRPCMining, free'd in ShutdownRPCMining
static CReserveKey* pMiningKey = NULL;

void InitRPCMining()
{
    if (!pwalletMain)
        return;

    // getwork/getblocktemplate mining rewards paid here:
    pMiningKey = new CReserveKey(pwalletMain);
}

void ShutdownRPCMining()
{
    if (!pMiningKey)
        return;

    delete pMiningKey; pMiningKey = NULL;
}

value getgenerate(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 0)
        throw runtime_error(
            "getgenerate\n"
            "Returns true or false.");

    if (!pMiningKey)
        return false;

    return user_options["gen"].as<bool>();
}


value setgenerate(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 2)
        throw runtime_error(
            "setgenerate <generate> [genproclimit]\n"
            "<generate> is true or false to turn generation on or off.\n"
            "Generation is limited to [genproclimit] processors, -1 is unlimited.");

    bool fGenerate = true;
    if (params.length() > 0)
        fGenerate = params[0].get_as<bool>();

    if (params.length() > 1)
    {

      unsigned int nGenProcLimit = params[1].get_as<unsigned int>();
      update_config("--genproclimit"
		    , itostr(nGenProcLimit));

      if (nGenProcLimit == 0) {
	fGenerate = false;
      }
    }
    update_config("--gen", (fGenerate ? "1" : "0"));

    assert(pwalletMain != NULL);
    GenerateBitcoins(fGenerate, pwalletMain);
    return null_t();
}


value gethashespersec(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 0)
        throw runtime_error(
            "gethashespersec\n"
            "Returns a recent hashes per second performance measurement while generating.");

    if (GetTimeMillis() - nHPSTimerStart > 8000)
        return (boost::int64_t)0;
    return (boost::int64_t)dHashesPerSec;
}


value getmininginfo(const value& params, bool fHelp)
{
    if (fHelp || params.length() != 0)
        throw runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");

    value obj = object()
      ("blocks",        (int)nBestHeight)
      ("currentblocksize",(uint64_t)nLastBlockSize)
      ("currentblocktx",(uint64_t)nLastBlockTx)
      ("difficulty",    (double)GetDifficulty())
      ("errors",        GetWarnings("statusbar"))
      ("generate",      user_options["gen"].as<bool>())
      ("genproclimit",  user_options["genproclimit"].as<int>())
      ("hashespersec",  gethashespersec(params, false))
      ("networkhashps", getnetworkhashps(params, false))
      ("pooledtx",      (uint64_t)mempool.size())
      ("testnet",       user_options.count("testnet") and user_options["testnet"].as<bool>())
      ;

    return obj;
}


value getworkex(const value& params, bool fHelp)
{
    if (fHelp || params.length() > 2)
        throw runtime_error(
            "getworkex [data, coinbase]\n"
            "If [data, coinbase] is not specified, returns extended work data.\n"
        );

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Litecoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Litecoin is downloading blocks...");

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
    static vector<CBlockTemplate*> vNewBlockTemplate;
    static CReserveKey reservekey(pwalletMain);

    if (params.length() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64 nStart;
        static CBlockTemplate* pblocktemplate;
        if (pindexPrev != pindexBest ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlockTemplate* pblocktemplate, vNewBlockTemplate)
                    delete pblocktemplate;
                vNewBlockTemplate.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = NULL;

            // Store the pindexBest used before CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = nTransactionsUpdated;
            CBlockIndex* pindexPrevNew = pindexBest;
            nStart = GetTime();

            // Create new block
            pblocktemplate = CreateNewBlockWithKey(*pMiningKey);
            if (!pblocktemplate)
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            vNewBlockTemplate.push_back(pblocktemplate);

            // Need to update only after we know CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }
        CBlock* pblock = &pblocktemplate->block; // pointer for convenience

        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        CTransaction coinbaseTx = pblock->vtx[0];
        std::vector<uint256> merkle = pblock->GetMerkleBranch(0);

        value result = object()
	  ("data",     HexStr(BEGIN(pdata), END(pdata)))
	  ("target",   HexStr(BEGIN(hashTarget), END(hashTarget)))
	  ;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << coinbaseTx;
        result["coinbase"] = HexStr(ssTx.begin(), ssTx.end());

        value merkle_arr;

        BOOST_FOREACH(uint256 merkleh, merkle) {
            printf("%s\n", merkleh.ToString().c_str());
            merkle_arr.push_back(HexStr(BEGIN(merkleh), END(merkleh)));
        }

        result["merkle"] = merkle_arr;

        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> vchData = ParseHex(params[0].get_as<std::string>());
        vector<unsigned char> coinbase;

        if(params.length() == 2)
            coinbase = ParseHex(params[1].get_as<std::string>());

        if (vchData.size() != 128)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
            
        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128/4; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;

        if(coinbase.size() == 0)
            pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        else
            CDataStream(coinbase, SER_NETWORK, PROTOCOL_VERSION) >> pblock->vtx[0];

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        return CheckWork(pblock, *pwalletMain, reservekey);
    }
}


value getwork(const value& params, bool fHelp)
{
    if (fHelp || params.length() > 1)
        throw runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Litecoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Litecoin is downloading blocks...");

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
    static vector<CBlockTemplate*> vNewBlockTemplate;

    if (params.length() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64 nStart;
        static CBlockTemplate* pblocktemplate;
        if (pindexPrev != pindexBest ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlockTemplate* pblocktemplate, vNewBlockTemplate)
                    delete pblocktemplate;
                vNewBlockTemplate.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = NULL;

            // Store the pindexBest used before CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = nTransactionsUpdated;
            CBlockIndex* pindexPrevNew = pindexBest;
            nStart = GetTime();

            // Create new block
            pblocktemplate = CreateNewBlockWithKey(*pMiningKey);
            if (!pblocktemplate)
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            vNewBlockTemplate.push_back(pblocktemplate);

            // Need to update only after we know CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }
        CBlock* pblock = &pblocktemplate->block; // pointer for convenience

        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        value result = object()
	  ("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))
	  ("data",     HexStr(BEGIN(pdata), END(pdata)))
	  ("hash1",    HexStr(BEGIN(phash1), END(phash1)))
	  ("target",   HexStr(BEGIN(hashTarget), END(hashTarget)))
	  ;
        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> vchData = ParseHex(params[0].get_as<std::string>());
        if (vchData.size() != 128)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128/4; i++)
            ((unsigned int*)pdata)[i] = ByteReverse(((unsigned int*)pdata)[i]);

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;
        pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        assert(pwalletMain != NULL);
        return CheckWork(pblock, *pwalletMain, *pMiningKey);
    }
}


value getblocktemplate(const value& params, bool fHelp)
{
    if (fHelp || params.length() > 1)
        throw runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::string strMode = "template";
    if (params.length() > 0)
    {
      const value& oparam = params[0];
      const value& modeval = oparam["mode"];
      if (modeval.type() == string_type) {
	strMode = modeval.get_as<std::string>();
      } else if (modeval == null_t()) {
	;
      } else {
	throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
      }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Litecoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Litecoin is downloading blocks...");

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64 nStart;
    static CBlockTemplate* pblocktemplate;
    if (pindexPrev != pindexBest ||
        (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrevNew = pindexBest;
        nStart = GetTime();

        // Create new block
        if(pblocktemplate)
        {
            delete pblocktemplate;
            pblocktemplate = NULL;
        }
        CScript scriptDummy = CScript() << OP_TRUE;
        pblocktemplate = CreateNewBlock(scriptDummy);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    value transactions = array();
    map<uint256, int64_t> setTxIndex;
    int i = 0;
    BOOST_FOREACH (CTransaction& tx, pblock->vtx) {
      uint256 txHash = tx.GetHash();
      setTxIndex[txHash] = i++;

      if (tx.IsCoinBase()) {
	continue;
      }

      value entry = object();
      
      CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
      ssTx << tx;
      entry["data"] = HexStr(ssTx.begin(), ssTx.end());
      entry["hash"] = txHash.GetHex();

      value deps = array();
      BOOST_FOREACH (const CTxIn &in, tx.vin) {
	if (setTxIndex.count(in.prevout.hash)) {
	  deps.push_back(setTxIndex[in.prevout.hash]);
	}
      }
      entry["depends"] = deps;

      int index_in_template = i - 1;
      entry["fee"] = pblocktemplate->vTxFees[index_in_template];
      entry["sigops"] = pblocktemplate->vTxSigOps[index_in_template];

      transactions.push_back(entry);
    }

    value aux = object()("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end()));

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    static value aMutable = array();
    if (aMutable.length() == 0)
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    value result = object()
      ("version", pblock->nVersion)
      ("previousblockhash", pblock->hashPrevBlock.GetHex())
      ("transactions", transactions)
      ("coinbaseaux", aux)
      ("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue)
      ("target", hashTarget.GetHex())
      ("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1)
      ("mutable", aMutable)
      ("noncerange", "00000000ffffffff")
      ("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS)
      ("sizelimit", (int64_t)MAX_BLOCK_SIZE)
      ("curtime", (int64_t)pblock->nTime)
      ("bits", HexBits(pblock->nBits))
      ("height", (int64_t)(pindexPrev->nHeight+1))
      ;

    return result;
}

value submitblock(const value& params, bool fHelp)
{
    if (fHelp || params.length() < 1 || params.length() > 2)
        throw runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    vector<unsigned char> blockData(ParseHex(params[0].get_as<std::string>()));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    CBlock pblock;
    try {
        ssBlock >> pblock;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    CValidationState state;
    bool fAccepted = ProcessBlock(state, NULL, &pblock);
    if (!fAccepted)
        return "rejected"; // TODO: report validation state

    return null_t();
}
