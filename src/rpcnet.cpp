// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net.h"
#include "bitcoinrpc.h"

#include "ciere/json/value.hpp"

using namespace ciere::json;
using namespace std;

value getconnectioncount(const value& params, bool fHelp)
{
  if (fHelp or params.length() != 0) {
    throw runtime_error("getconnectioncount\n"
			"Returns the number of connections to other nodes.");
  }
  
  LOCK(cs_vNodes);
  return (int)vNodes.size();
  
}

static void CopyNodeStats(std::vector<CNodeStats>& vstats)
{
  vstats.clear();
  
  LOCK(cs_vNodes);
  vstats.reserve(vNodes.size());
  BOOST_FOREACH(CNode* pnode, vNodes) {
    CNodeStats stats;
    pnode->copyStats(stats);
    vstats.push_back(stats);
  }
}

value getpeerinfo(const value& params, bool fHelp) {
  if (fHelp || params.length() != 0) {
    throw runtime_error("getpeerinfo\n"
			"Returns data about each connected network node.");
  }
  
  vector<CNodeStats> vstats;
  CopyNodeStats(vstats);
  
  value ret = array();
  
  BOOST_FOREACH(const CNodeStats& stats, vstats) {
    value obj = object()
      ("addr", stats.addrName)
      ("services", strprintf("%08"PRI64x, stats.nServices))
      ("lastsend", (boost::int64_t)stats.nLastSend)
      ("lastrecv", (boost::int64_t)stats.nLastRecv)
      ("bytessent", (boost::int64_t)stats.nSendBytes)
      ("bytesrecv", (boost::int64_t)stats.nRecvBytes)
      ("blocksrequested", (boost::int64_t)stats.nBlocksRequested)
      ("conntime", (boost::int64_t)stats.nTimeConnected)
      ("version", stats.nVersion)
      // Use the sanitized form of subver here, to avoid tricksy remote peers from
      // corrupting or modifiying the JSON output by putting special characters in
      // their ver message.
      ("subver", stats.cleanSubVer)
      ("inbound", stats.fInbound)
      ("startingheight", stats.nStartingHeight)
      ("banscore", stats.nMisbehavior)
      ;
    
    if (stats.fSyncNode) {
      obj["syncnode"] = true;
    }
    
    ret.push_back(obj);
    
  }
  
  return ret;
}

value addnode(const value& params, bool fHelp)
{
  string strCommand;
  if (params.length() == 2) {
    strCommand = params[1].get_as<std::string>();
  }
  if (fHelp 
      or params.length() != 2 
      or (strCommand != "onetry" 
	  and strCommand != "add" 
	  and strCommand != "remove")) {
    throw runtime_error("addnode <node> <add|remove|onetry>\n"
			"Attempts add or remove <node> from the addnode list or try a connection to <node> once.");
  }
  
  string strNode = params[0].get_as<std::string>();
  
  if (strCommand == "onetry")
    {
      CAddress addr;
      ConnectNode(addr, strNode.c_str());
      return null_t();
    }
  
  LOCK(cs_vAddedNodes);
  vector<string>::iterator it = vAddedNodes.begin();
  for(; it != vAddedNodes.end(); it++)
    if (strNode == *it)
      break;
  
  if (strCommand == "add")
    {
      if (it != vAddedNodes.end())
	throw JSONRPCError(-23, "Error: Node already added");
      vAddedNodes.push_back(strNode);
    }
  else if(strCommand == "remove")
    {
      if (it == vAddedNodes.end())
	throw JSONRPCError(-24, "Error: Node has not been added.");
      vAddedNodes.erase(it);
    }
  
  return null_t();
}

value getaddednodeinfo(const value& params, bool fHelp)
{
  if (fHelp || params.length() < 1 || params.length() > 2)
    throw runtime_error(
			"getaddednodeinfo <dns> [node]\n"
			"Returns information about the given added node, or all added nodes\n"
			"(note that onetry addnodes are not listed here)\n"
			"If dns is false, only a list of added nodes will be provided,\n"
			"otherwise connected information will also be available.");
  
  bool fDns = params[0].get_as<bool>();
  
  list<string> laddedNodes(0);
  if (params.length() == 1)
    {
      LOCK(cs_vAddedNodes);
      BOOST_FOREACH(string& strAddNode, vAddedNodes)
	laddedNodes.push_back(strAddNode);
    }
  else
    {
      string strNode = params[1].get_as<std::string>();
      LOCK(cs_vAddedNodes);
      BOOST_FOREACH(string& strAddNode, vAddedNodes)
	if (strAddNode == strNode)
	  {
	    laddedNodes.push_back(strAddNode);
	    break;
	  }
      if (laddedNodes.size() == 0)
	throw JSONRPCError(-24, "Error: Node has not been added.");
    }
  
  if (!fDns)
    {
      value ret;
      BOOST_FOREACH(string& strAddNode, laddedNodes) {
	ret["addednode"] = strAddNode;
      }
      return ret;
    }
  
  value ret;
  
  list<pair<string, vector<CService> > > laddedAddreses(0);
  BOOST_FOREACH(string& strAddNode, laddedNodes)
    {
      vector<CService> vservNode(0);
      if(Lookup(strAddNode.c_str(), vservNode, user_options["port"].as<unsigned int>(), fNameLookup, 0))
	laddedAddreses.push_back(make_pair(strAddNode, vservNode));
      else
        {
	  value addresses;
	  value obj = object()
	    ("addednode", strAddNode)
	    ("connected", false)
	    ("addresses", addresses)
	    ;
        }
    }
  
  LOCK(cs_vNodes);
  for (list<pair<string, vector<CService> > >::iterator it = laddedAddreses.begin(); it != laddedAddreses.end(); it++) {
    value obj = object()("addednode", it->first);
    
    value addresses = array();
    bool fConnected = false;
    BOOST_FOREACH(CService& addrNode, it->second) {
      bool fFound = false;
      value node = object()("address", addrNode.ToString());
      BOOST_FOREACH(CNode* pnode, vNodes) {
	if (pnode->addr == addrNode) {
	  fFound = true;
	  fConnected = true;
	  node["connected"] = pnode->fInbound ? "inbound" : "outbound";
	  break;
	}
      }
      if (!fFound) {
	node["connected"] = "false";
      }
      addresses.push_back(node);
    }
    obj["connected"] = fConnected;
    obj["addresses"] = addresses;
    ret.push_back(obj);
  }
  
  return ret;
}

