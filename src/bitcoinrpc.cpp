// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "util.h"
#include "sync.h"
#include "ui_interface.h"
#include "base58.h"
#include "bitcoinrpc.h"
#include "db.h"

#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/assign.hpp>
#include <list>

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace ciere::json;

namespace fs = boost::filesystem;

static std::map<value_types, std::string> value_type_name = 
  boost::assign::map_list_of
  (string_type, "string")
  (double_type, "double")
  (int_type, "integer")
  (bool_type, "boolean")
  (null_type, "null")
  (value_type, "value")
  (object_type, "object")
  (array_type, "array")
  ;

static std::string strRPCUserColonPass;

// These are created by StartRPCThreads, destroyed in StopRPCThreads
static asio::io_service* rpc_io_service = NULL;
static ssl::context* rpc_ssl_context = NULL;
static boost::thread_group* rpc_worker_group = NULL;

static inline unsigned short GetDefaultRPCPort()
{
  return user_options["testnet"].as<bool>() ? 19332 : 9332;
}

value JSONRPCError(int code, const string& message)
{
  return object()
    ("code", code)
    ("message", message)
    ;
}

void RPCTypeCheck(const value& params,
                  const list<value_types>& typesExpected,
                  bool fAllowNull)
{
  unsigned int i = 0;
  BOOST_FOREACH(value_types t, typesExpected)
    {
      if (params.length() <= i)
	break;
      
      const value& v = params[i];
      if (!((v.type() == t) || (fAllowNull && (v.type() == null_type))))
        {
	  string err = strprintf("Expected type %s, got %s"
				 , value_type_name[t].c_str()
				 , value_type_name[v.type()].c_str());
	  throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
      i++;
    }
}

void RPCTypeCheck(const value& o,
                  const map<string, value_types>& typesExpected,
                  bool fAllowNull)
{
  BOOST_FOREACH(const PAIRTYPE(string, value_types)& t, typesExpected)
    {
      const value& v = o[t.first];
      if (!fAllowNull && v.type() == null_type)
	throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first.c_str()));
      
      if (!((v.type() == t.second) || (fAllowNull && (v.type() == null_type))))
        {
	  string err = strprintf("Expected type %s for %s, got %s"
				 , value_type_name[t.second].c_str()
				 , t.first.c_str()
				 , value_type_name[v.type()].c_str());
	  throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

int64 AmountFromValue(const value& value)
{
  double dAmount = value.get_as<double>();
  if (dAmount <= 0.0 || dAmount > 84000000.0)
    throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
  int64 nAmount = roundint64(dAmount * COIN);
  if (!MoneyRange(nAmount))
    throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
  return nAmount;
}

value ValueFromAmount(int64 amount)
{
  return (double)amount / (double)COIN;
}

std::string HexBits(unsigned int nBits)
{
  union {
    int32_t nBits;
    char cBits[4];
  } uBits;
  uBits.nBits = htonl((int32_t)nBits);
  return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}



///
/// Note: This interface may still be subject to change.
///

string CRPCTable::help(string strCommand) const
{
  string strRet;
  set<rpcfn_type> setDone;
  for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin()
	 ; mi != mapCommands.end()
	 ; ++mi)
    {
        const CRPCCommand *pcmd = mi->second;
        string strMethod = mi->first;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;
        if (strCommand != "" && strMethod != strCommand)
            continue;
        if (pcmd->reqWallet && !pwalletMain)
            continue;

        try
        {
            value params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

value help(const value& params, bool fHelp)
{
  if (fHelp or params.type() != array_type or params.length() > 1)
    throw runtime_error("help [command]\n"
			"List commands, or get help for a command.");

    string strCommand;
    if (params.length() > 0)
      strCommand = params[0].get_as<std::string>();

    return tableRPC.help(strCommand);
}


value stop(const value& params, bool fHelp)
{
    // Accept the deprecated and ignored 'detach' boolean argument
  if (fHelp or params.type() != array_type or params.length() > 1)
    throw runtime_error("stop\n"
			"Stop TrollCoin server.");
    // Shutdown will take long enough that the response should get back
    StartShutdown();
    return "TrollCoin server stopping";
}



//
// Call Table
//


static const CRPCCommand vRPCCommands[] =
{ //  name                      actor (function)         okSafeMode threadSafe reqWallet
  //  ------------------------  -----------------------  ---------- ---------- ---------
    { "help",                   &help,                   true,      true,       false },
    { "stop",                   &stop,                   true,      true,       false },
    { "getblockcount",          &getblockcount,          true,      false,      false },
    { "getbestblockhash",       &getbestblockhash,       true,      false,      false },
    { "getconnectioncount",     &getconnectioncount,     true,      false,      false },
    { "getpeerinfo",            &getpeerinfo,            true,      false,      false },
    { "addnode",                &addnode,                true,      true,       false },
    { "getaddednodeinfo",       &getaddednodeinfo,       true,      true,       false },
    { "getdifficulty",          &getdifficulty,          true,      false,      false },
    { "getnetworkhashps",       &getnetworkhashps,       true,      false,      false },
    { "getgenerate",            &getgenerate,            true,      false,      false },
    { "setgenerate",            &setgenerate,            true,      false,      true },
    { "gethashespersec",        &gethashespersec,        true,      false,      false },
    { "getinfo",                &getinfo,                true,      false,      false },
    { "getmininginfo",          &getmininginfo,          true,      false,      false },
    { "getnewaddress",          &getnewaddress,          true,      false,      true },
    { "getaccountaddress",      &getaccountaddress,      true,      false,      true },
    { "setaccount",             &setaccount,             true,      false,      true },
    { "getaccount",             &getaccount,             false,     false,      true },
    { "getaddressesbyaccount",  &getaddressesbyaccount,  true,      false,      true },
    { "sendtoaddress",          &sendtoaddress,          false,     false,      true },
    { "getreceivedbyaddress",   &getreceivedbyaddress,   false,     false,      true },
    { "getreceivedbyaccount",   &getreceivedbyaccount,   false,     false,      true },
    { "listreceivedbyaddress",  &listreceivedbyaddress,  false,     false,      true },
    { "listreceivedbyaccount",  &listreceivedbyaccount,  false,     false,      true },
    { "backupwallet",           &backupwallet,           true,      false,      true },
    { "keypoolrefill",          &keypoolrefill,          true,      false,      true },
    { "walletpassphrase",       &walletpassphrase,       true,      false,      true },
    { "walletpassphrasechange", &walletpassphrasechange, false,     false,      true },
    { "walletlock",             &walletlock,             true,      false,      true },
    { "encryptwallet",          &encryptwallet,          false,     false,      true },
    { "validateaddress",        &validateaddress,        true,      false,      false },
    { "getbalance",             &getbalance,             false,     false,      true },
    { "move",                   &movecmd,                false,     false,      true },
    { "sendfrom",               &sendfrom,               false,     false,      true },
    { "sendmany",               &sendmany,               false,     false,      true },
    { "addmultisigaddress",     &addmultisigaddress,     false,     false,      true },
    { "createmultisig",         &createmultisig,         true,      true ,      false },
    { "getrawmempool",          &getrawmempool,          true,      false,      false },
    { "getblock",               &getblock,               false,     false,      false },
    { "getblockhash",           &getblockhash,           false,     false,      false },
    { "gettransaction",         &gettransaction,         false,     false,      true },
    { "listtransactions",       &listtransactions,       false,     false,      true },
    { "listaddressgroupings",   &listaddressgroupings,   false,     false,      true },
    { "signmessage",            &signmessage,            false,     false,      true },
    { "verifymessage",          &verifymessage,          false,     false,      false },
    { "getwork",                &getwork,                true,      false,      true },
    { "getworkex",              &getworkex,              true,      false,      true },
    { "listaccounts",           &listaccounts,           false,     false,      true },
    { "settxfee",               &settxfee,               false,     false,      true },
    { "getblocktemplate",       &getblocktemplate,       true,      false,      false },
    { "submitblock",            &submitblock,            false,     false,      false },
    { "setmininput",            &setmininput,            false,     false,      false },
    { "listsinceblock",         &listsinceblock,         false,     false,      true },
    { "dumpprivkey",            &dumpprivkey,            true,      false,      true },
    { "importprivkey",          &importprivkey,          false,     false,      true },
    { "listunspent",            &listunspent,            false,     false,      true },
    { "getrawtransaction",      &getrawtransaction,      false,     false,      false },
    { "createrawtransaction",   &createrawtransaction,   false,     false,      false },
    { "decoderawtransaction",   &decoderawtransaction,   false,     false,      false },
    { "signrawtransaction",     &signrawtransaction,     false,     false,      false },
    { "sendrawtransaction",     &sendrawtransaction,     false,     false,      false },
    { "gettxoutsetinfo",        &gettxoutsetinfo,        true,      false,      false },
    { "gettxout",               &gettxout,               true,      false,      false },
    { "lockunspent",            &lockunspent,            false,     false,      true },
    { "listlockunspent",        &listlockunspent,        false,     false,      true },
    { "verifychain",            &verifychain,            true,      false,      false },
};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](string name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg, const map<string,string>& mapRequestHeaders)
{
    ostringstream s;
    s << "POST / HTTP/1.1\r\n"
      << "User-Agent: trollcoin-json-rpc/" << FormatFullVersion() << "\r\n"
      << "Host: 127.0.0.1\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << strMsg.size() << "\r\n"
      << "Connection: close\r\n"
      << "Accept: application/json\r\n";
    BOOST_FOREACH(const PAIRTYPE(string, string)& item, mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

string rfc1123Time()
{
    char buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want POSIX (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg, bool keepalive)
{
    if (nStatus == HTTP_UNAUTHORIZED)
        return strprintf("HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: trollcoin-json-rpc/%s\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", rfc1123Time().c_str(), FormatFullVersion().c_str());
    const char *cStatus;
         if (nStatus == HTTP_OK) cStatus = "OK";
    else if (nStatus == HTTP_BAD_REQUEST) cStatus = "Bad Request";
    else if (nStatus == HTTP_FORBIDDEN) cStatus = "Forbidden";
    else if (nStatus == HTTP_NOT_FOUND) cStatus = "Not Found";
    else if (nStatus == HTTP_INTERNAL_SERVER_ERROR) cStatus = "Internal Server Error";
    else cStatus = "";
    return strprintf(
            "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Connection: %s\r\n"
            "Content-Length: %"PRIszu"\r\n"
            "Content-Type: application/json\r\n"
            "Server: trollcoin-json-rpc/%s\r\n"
            "\r\n"
            "%s",
        nStatus,
        cStatus,
        rfc1123Time().c_str(),
        keepalive ? "keep-alive" : "close",
        strMsg.size(),
        FormatFullVersion().c_str(),
        strMsg.c_str());
}

bool ReadHTTPRequestLine(std::basic_istream<char>& stream, int &proto,
                         string& http_method, string& http_uri)
{
    string str;
    getline(stream, str);

    // HTTP request line is space-delimited
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return false;

    // HTTP methods permitted: GET, POST
    http_method = vWords[0];
    if (http_method != "GET" && http_method != "POST")
        return false;

    // HTTP URI must be an absolute path, relative to current host
    http_uri = vWords[1];
    if (http_uri.size() == 0 || http_uri[0] != '/')
        return false;

    // parse proto, if present
    string strProto = "";
    if (vWords.size() > 2)
        strProto = vWords[2];

    proto = 0;
    const char *ver = strstr(strProto.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);

    return true;
}

int ReadHTTPStatus(std::basic_istream<char>& stream, int &proto)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return HTTP_INTERNAL_SERVER_ERROR;
    proto = 0;
    const char *ver = strstr(str.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeaders(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    loop
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos)
        {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon+1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

int ReadHTTPMessage(std::basic_istream<char>& stream, map<string,
                    string>& mapHeadersRet, string& strMessageRet,
                    int nProto)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read header
    int nLen = ReadHTTPHeaders(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)MAX_SIZE)
        return HTTP_INTERNAL_SERVER_ERROR;

    // Read message
    if (nLen > 0)
    {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = string(vch.begin(), vch.end());
    }

    string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive"))
    {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return HTTP_OK;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0,6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    string strUserPass = DecodeBase64(strUserPass64);
    return TimingResistantEqual(strUserPass, strRPCUserColonPass);
}

//
// JSON-RPC protocol.  Trollcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const value& params, const value& id)
{
  value request = object()
    ("method", strMethod)
    ("params", params)
    ("id", id)
    ;
  std::stringstream ss;
  ss << request << std::endl;
  return ss.str();
}

value JSONRPCReplyObj(const value& result, const value& error, const value& id)
{
  value reply = object()
    ("error", error)
    ("id", id)
    ;

  if (error != null_t()) {
    reply["result"] = null_t();
  } else {
    reply["result"] = result;
  }
  return reply;
}

string JSONRPCReply(const value& result, const value& error, const value& id)
{
    value reply = JSONRPCReplyObj(result, error, id);
    std::stringstream ss;
    ss << reply << std::endl;
    return ss.str();
}

void ErrorReply(std::ostream& stream, const value& objError, const value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = objError["code"].get_as<int>();
    if (code == RPC_INVALID_REQUEST) nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND) nStatus = HTTP_NOT_FOUND;
    string strReply = JSONRPCReply(null_t(), objError, id);
    stream << HTTPReply(nStatus, strReply, false) << std::flush;
}

bool ClientAllowed(const boost::asio::ip::address& address)
{
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
    if (address.is_v6()
     && (address.to_v6().is_v4_compatible()
      || address.to_v6().is_v4_mapped()))
        return ClientAllowed(address.to_v6().to_v4());

    if (address == asio::ip::address_v4::loopback()
     || address == asio::ip::address_v6::loopback()
     || (address.is_v4()
         // Check whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
      && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000))
        return true;

    const string strAddress = address.to_string();
    const vector<string>& vAllow = user_options["rpcallowip"].as< std::vector<std::string> >();
    BOOST_FOREACH(string strAllow, vAllow) {
      if (WildcardMatch(strAddress, strAllow)) {
	return true;
      }
    }
    return false;
}

//
// IOStream device that speaks SSL but can also speak non-SSL
//
template <typename Protocol>
class SSLIOStreamDevice : public iostreams::device<iostreams::bidirectional> {
public:
    SSLIOStreamDevice(asio::ssl::stream<typename Protocol::socket> &streamIn, bool fUseSSLIn) : stream(streamIn)
    {
        fUseSSL = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(ssl::stream_base::handshake_type role)
    {
        if (!fNeedHandshake) return;
        fNeedHandshake = false;
        stream.handshake(role);
    }
    std::streamsize read(char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL) return stream.read_some(asio::buffer(s, n));
        return stream.next_layer().read_some(asio::buffer(s, n));
    }
    std::streamsize write(const char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL) return asio::write(stream, asio::buffer(s, n));
        return asio::write(stream.next_layer(), asio::buffer(s, n));
    }
    bool connect(const std::string& server, const std::string& port)
    {
        ip::tcp::resolver resolver(stream.get_io_service());
        ip::tcp::resolver::query query(server.c_str(), port.c_str());
        ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        ip::tcp::resolver::iterator end;
        boost::system::error_code error = asio::error::host_not_found;
        while (error && endpoint_iterator != end)
        {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        if (error)
            return false;
        return true;
    }

private:
    bool fNeedHandshake;
    bool fUseSSL;
    asio::ssl::stream<typename Protocol::socket>& stream;
};

class AcceptedConnection
{
public:
    virtual ~AcceptedConnection() {}

    virtual std::iostream& stream() = 0;
    virtual std::string peer_address_to_string() const = 0;
    virtual void close() = 0;
};

template <typename Protocol>
class AcceptedConnectionImpl : public AcceptedConnection
{
public:
    AcceptedConnectionImpl(
            asio::io_service& io_service,
            ssl::context &context,
            bool fUseSSL) :
        sslStream(io_service, context),
        _d(sslStream, fUseSSL),
        _stream(_d)
    {
    }

    virtual std::iostream& stream()
    {
        return _stream;
    }

    virtual std::string peer_address_to_string() const
    {
        return peer.address().to_string();
    }

    virtual void close()
    {
        _stream.close();
    }

    typename Protocol::endpoint peer;
    asio::ssl::stream<typename Protocol::socket> sslStream;

private:
    SSLIOStreamDevice<Protocol> _d;
    iostreams::stream< SSLIOStreamDevice<Protocol> > _stream;
};

void ServiceConnection(AcceptedConnection *conn);

// Forward declaration required for RPCListen
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error);

/**
 * Sets up I/O resources to accept and handle a new connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCListen(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                   ssl::context& context,
                   const bool fUseSSL)
{
    // Accept connection
    AcceptedConnectionImpl<Protocol>* conn = new AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);

    acceptor->async_accept(
            conn->sslStream.lowest_layer(),
            conn->peer,
            boost::bind(&RPCAcceptHandler<Protocol, SocketAcceptorService>,
                acceptor,
                boost::ref(context),
                fUseSSL,
                conn,
                boost::asio::placeholders::error));
}

/**
 * Accept and handle incoming connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             const bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error)
{
    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != asio::error::operation_aborted && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL);

    AcceptedConnectionImpl<ip::tcp>* tcp_conn = dynamic_cast< AcceptedConnectionImpl<ip::tcp>* >(conn);

    // TODO: Actually handle errors
    if (error)
    {
        delete conn;
    }

    // Restrict callers by IP.  It is important to
    // do this before starting client thread, to filter out
    // certain DoS and misbehaving clients.
    else if (tcp_conn && !ClientAllowed(tcp_conn->peer.address()))
    {
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (!fUseSSL)
            conn->stream() << HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
        delete conn;
    }
    else {
        ServiceConnection(conn);
        conn->close();
        delete conn;
    }
}

void StartRPCThreads()
{
  strRPCUserColonPass = user_options["rpcuser"].as<std::string>() + ":" + user_options["rpcpassword"].as<std::string>();
  if ((user_options["rpcpassword"].as<std::string>() == "") 
      or (user_options["rpcuser"].as<std::string>() == user_options["rpcpassword"].as<std::string>())) {
    unsigned char rand_pwd[32];
    RAND_bytes(rand_pwd, 32);
    string strWhatAmI = "To use trollcoind";
    if (user_options.count("server")) {
      strWhatAmI = strprintf(_("To use the %s option"), "\"--server\"");
    } else if (user_options.count("daemon")) {
      strWhatAmI = strprintf(_("To use the %s option"), "\"--daemon\"");
    }
    uiInterface.ThreadSafeMessageBox(strprintf(
					       _("%s, you must set a rpcpassword in the configuration file:\n"
						 "%s\n"
						 "It is recommended you use the following random password:\n"
						 "rpcuser=trollcoinrpc\n"
						 "rpcpassword=%s\n"
						 "(you do not need to remember this password)\n"
						 "The username and password MUST NOT be the same.\n"
						 "If the file does not exist, create it with owner-readable-only file permissions.\n"
						 "It is also recommended to set alertnotify so you are notified of problems;\n"
						 "for example: alertnotify=echo %%s | mail -s \"TrollCoin Alert\" admin@foo.com\n"),
					       strWhatAmI.c_str(),
					       user_options["conf"].as<fs::path>().string().c_str(),
					       EncodeBase58(&rand_pwd[0],&rand_pwd[0]+32).c_str()),
				     "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return;
  }
  
  assert(rpc_io_service == NULL);
  rpc_io_service = new asio::io_service();
  rpc_ssl_context = new ssl::context(*rpc_io_service, ssl::context::sslv23);
  
  const bool fUseSSL = user_options["rpcssl"].as<bool>();
  
  if (fUseSSL)
    {
      rpc_ssl_context->set_options(ssl::context::no_sslv2);
      
      filesystem::path pathCertFile(user_options["rpcsslcertificatechainfile"].as<filesystem::path>());
      if (!pathCertFile.is_complete()) pathCertFile = user_options["datadir"].as<filesystem::path>() / pathCertFile;
      if (filesystem::exists(pathCertFile)) rpc_ssl_context->use_certificate_chain_file(pathCertFile.string());
      else printf("ThreadRPCServer ERROR: missing server certificate file %s\n", pathCertFile.string().c_str());
      
      filesystem::path pathPKFile(user_options["rpcsslprivatekeyfile"].as<filesystem::path>());
      if (!pathPKFile.is_complete()) pathPKFile = filesystem::path(user_options["datadir"].as<fs::path>()) / pathPKFile;
      if (filesystem::exists(pathPKFile)) rpc_ssl_context->use_private_key_file(pathPKFile.string(), ssl::context::pem);
      else printf("ThreadRPCServer ERROR: missing server private key file %s\n", pathPKFile.string().c_str());
      
      string strCiphers = user_options["rpcsslciphers"].as<std::string>();
      SSL_CTX_set_cipher_list(rpc_ssl_context->impl(), strCiphers.c_str());
    }
  
  // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
  const bool loopback = !user_options.count("rpcallowip") and user_options["rpcallowip"].as<bool>();
  asio::ip::address bindAddress = loopback ? asio::ip::address_v6::loopback() : asio::ip::address_v6::any();
  ip::tcp::endpoint endpoint(bindAddress, user_options["rpcport"].as<unsigned int>());
  boost::system::error_code v6_only_error;
  boost::shared_ptr<ip::tcp::acceptor> acceptor(new ip::tcp::acceptor(*rpc_io_service));
  
  bool fListening = false;
  std::string strerr;
  try
    {
      acceptor->open(endpoint.protocol());
      acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
      
      // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
      acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);
      
      acceptor->bind(endpoint);
      acceptor->listen(socket_base::max_connections);
      
      RPCListen(acceptor, *rpc_ssl_context, fUseSSL);
      
      fListening = true;
    }
  catch(boost::system::system_error &e)
    {
      strerr = strprintf(_("An error occurred while setting up the RPC port %u for listening on IPv6, falling back to IPv4: %s"), endpoint.port(), e.what());
    }
  
  try {
    // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
    if (!fListening || loopback || v6_only_error)
      {
	bindAddress = loopback ? asio::ip::address_v4::loopback() : asio::ip::address_v4::any();
	endpoint.address(bindAddress);
	
	acceptor.reset(new ip::tcp::acceptor(*rpc_io_service));
	acceptor->open(endpoint.protocol());
	acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
	acceptor->bind(endpoint);
	acceptor->listen(socket_base::max_connections);
	
	RPCListen(acceptor, *rpc_ssl_context, fUseSSL);
	
	fListening = true;
      }
  }
  catch(boost::system::system_error &e)
    {
      strerr = strprintf(_("An error occurred while setting up the RPC port %u for listening on IPv4: %s"), endpoint.port(), e.what());
    }
  
  if (!fListening) {
    uiInterface.ThreadSafeMessageBox(strerr, "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return;
  }
  
  rpc_worker_group = new boost::thread_group();
  for (unsigned int i = 0; i < user_options["rpcthreads"].as<unsigned int>(); i++) {
    rpc_worker_group->create_thread(boost::bind(&asio::io_service::run, rpc_io_service));
  }
}

void StopRPCThreads()
{
  if (rpc_io_service == NULL) return;
  
  rpc_io_service->stop();
  rpc_worker_group->join_all();
  delete rpc_worker_group; rpc_worker_group = NULL;
  delete rpc_ssl_context; rpc_ssl_context = NULL;
  delete rpc_io_service; rpc_io_service = NULL;
}

class JSONRequest
{
public:
  value id;
  string strMethod;
  value params;
  
  JSONRequest() { id = null_t(); }
  void parse(const value& valRequest);
};

void JSONRequest::parse(const value& request)
{
  // Parse request
  if (request.type() != object_type)
    throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
  
  // Parse id now so errors from here on will have the id
  id = request["id"].get_as<std::string>();
  
  // Parse method
  value valMethod = request["method"];
  if (valMethod.type() == null_type)
    throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
  if (valMethod.type() != string_type)
    throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
  strMethod = valMethod.get_as<std::string>();
  if (strMethod != "getwork" and strMethod != "getworkex" and strMethod != "getblocktemplate")
    printf("ThreadRPCServer method=%s\n", strMethod.c_str());
  
  // Parse params
  value valParams = request["params"];
  if (valParams.type() == array_type or valParams == null_t())
    params = valParams;
  else
    throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
}

static value JSONRPCExecOne(const value& req)
{
  value rpc_result;
  
  JSONRequest jreq;
  try {
    jreq.parse(req);
    
    value result = tableRPC.execute(jreq.strMethod, jreq.params);
    rpc_result = JSONRPCReplyObj(result, null_t(), jreq.id);
  }
  catch (object_t& objError)
    {
      rpc_result = JSONRPCReplyObj(null_t(), objError, jreq.id);
    }
  catch (std::exception& e)
    {
      rpc_result = JSONRPCReplyObj(null_t(),
				   JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }
  
  return rpc_result;
}

static string JSONRPCExecBatch(const value& vReq)
{
  value ret;
  for (unsigned int reqIdx = 0; reqIdx < vReq.length(); reqIdx++) {
    ret.push_back(JSONRPCExecOne(vReq[reqIdx]));
  }
  stringstream ss;
  ss << ret;
  
  return ss.str() + "\n";
}

void ServiceConnection(AcceptedConnection *conn)
{
  bool fRun = true;
  while (fRun)
    {
      int nProto = 0;
      map<string, string> mapHeaders;
      string strRequest, strMethod, strURI;
      
      // Read HTTP request line
      if (!ReadHTTPRequestLine(conn->stream(), nProto, strMethod, strURI))
	break;
      
      // Read HTTP message headers and body
      ReadHTTPMessage(conn->stream(), mapHeaders, strRequest, nProto);
      
      if (strURI != "/") {
	conn->stream() << HTTPReply(HTTP_NOT_FOUND, "", false) << std::flush;
	break;
      }
      
      // Check authorization
      if (mapHeaders.count("authorization") == 0)
        {
	  conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
	  break;
        }
      if (!HTTPAuthorized(mapHeaders))
        {
	  printf("ThreadRPCServer incorrect password attempt from %s\n", conn->peer_address_to_string().c_str());
	  /* Deter brute-forcing short passwords.
	     If this results in a DOS the user really
	     shouldn't have their RPC port exposed.*/
	  if (user_options["rpcpassword"].as<std::string>().size() < 20) {
	    MilliSleep(250);
	  }
	  
	  conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
	  break;
        }
      if (mapHeaders["connection"] == "close")
	fRun = false;
      
      JSONRequest jreq;
      try
        {
	  // Parse request
	  value valRequest;
	  if (!construct(strRequest, valRequest))
	    throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");
	  
	  string strReply;
	  
	  // singleton request
	  if (valRequest.type() == object_type) {
	    jreq.parse(valRequest);
	    
	    value result = tableRPC.execute(jreq.strMethod, jreq.params);
	    
	    // Send reply
	    strReply = JSONRPCReply(result, null_t(), jreq.id);
	    
            // array of requests
	  } else if (valRequest.type() == array_type)
	    strReply = JSONRPCExecBatch(valRequest);
	  else
	    throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");
	  
	  conn->stream() << HTTPReply(HTTP_OK, strReply, fRun) << std::flush;
        }
      catch (object_t& objError)
        {
	  ErrorReply(conn->stream(), objError, jreq.id);
	  break;
        }
      catch (std::exception& e)
        {
	  ErrorReply(conn->stream(), JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
	  break;
        }
    }
}

value CRPCTable::execute(const std::string &strMethod, const value &params) const
{
  // Find method
  const CRPCCommand *pcmd = tableRPC[strMethod];
  if (!pcmd)
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");
  if (pcmd->reqWallet && !pwalletMain)
    throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found (disabled)");
  
  // Observe safe mode
  string strWarning = GetWarnings("rpc");
  if (strWarning != "" and !user_options["disablesafemode"].as<bool>() and !pcmd->okSafeMode) {
    throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);
  }
  
  try
    {
      // Execute
      value result;
      {
	if (pcmd->threadSafe)
	  result = pcmd->actor(params, false);
	else if (!pwalletMain) {
	  LOCK(cs_main);
	  result = pcmd->actor(params, false);
	} else {
	  LOCK2(cs_main, pwalletMain->cs_wallet);
	  result = pcmd->actor(params, false);
	}
      }
      return result;
    }
  catch (std::exception& e)
    {
      throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}


value CallRPC(const string& strMethod, const value& params)
{
  if (user_options["rpcuser"].as<std::string>() == "" 
      and user_options["rpcpassword"].as<std::string>() == "") {
    throw runtime_error(strprintf(_("You must set rpcpassword=<password> in the configuration file:\n%s\n"
				    "If the file does not exist, create it with owner-readable-only file permissions."),
				  user_options["conf"].as<fs::path>().string().c_str()));
  }
  
  // Connect to localhost
  bool fUseSSL = user_options["rpcssl"].as<bool>();
  asio::io_service io_service;
  ssl::context context(io_service, ssl::context::sslv23);
  context.set_options(ssl::context::no_sslv2);
  asio::ssl::stream<asio::ip::tcp::socket> sslStream(io_service, context);
  SSLIOStreamDevice<asio::ip::tcp> d(sslStream, fUseSSL);
  iostreams::stream< SSLIOStreamDevice<asio::ip::tcp> > stream(d);
  if (!d.connect(user_options["rpcconnect"].as<std::string>(), user_options["rpcport"].as<std::string>())) {
    throw runtime_error("couldn't connect to server");
  }
  
  // HTTP basic authentication
  string strUserPass64 = EncodeBase64(user_options["rpcuser"].as<std::string>() + ":" + user_options["rpcpassword"].as<std::string>());
  map<string, string> mapRequestHeaders;
  mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;
  
  // Send request
  string strRequest = JSONRPCRequest(strMethod, params, 1);
  string strPost = HTTPPost(strRequest, mapRequestHeaders);
  stream << strPost << std::flush;
  
  // Receive HTTP reply status
  int nProto = 0;
  int nStatus = ReadHTTPStatus(stream, nProto);
  
  // Receive HTTP reply message headers and body
  map<string, string> mapHeaders;
  string strReply;
  ReadHTTPMessage(stream, mapHeaders, strReply, nProto);
  
  if (nStatus == HTTP_UNAUTHORIZED)
    throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
  else if (nStatus >= 400 && nStatus != HTTP_BAD_REQUEST && nStatus != HTTP_NOT_FOUND && nStatus != HTTP_INTERNAL_SERVER_ERROR)
    throw runtime_error(strprintf("server returned HTTP error %d", nStatus));
  else if (strReply.empty())
    throw runtime_error("no response from server");
  
  // Parse reply
  value valReply;
  stringstream ss(strReply);
  if (!construct(ss, valReply)) {
    throw runtime_error("couldn't parse reply from server");
  }
  if (valReply.type() != object_type or valReply.length() == 0) {
    throw runtime_error("expected reply to have result, error and id properties");
  }
  
  return valReply;
}


// Convert strings to command-specific RPC representation
value RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
  value params;
  BOOST_FOREACH(const std::string &param, strParams) {
    value v;
    construct(param, v);
    params.push_back(v);
  }
  return params;
}

int CommandLineRPC(int argc, char *argv[])
{
  string strPrint;
  int nRet = 0;
  try
    {
      // Skip switches
      while (argc > 1 && IsSwitchChar(argv[1][0]))
        {
	  argc--;
	  argv++;
        }
      
      // Method
      if (argc < 2)
	throw runtime_error("too few parameters");
      string strMethod = argv[1];
      
      // Parameters default to strings
      std::vector<std::string> strParams(&argv[2], &argv[argc]);
      value params = RPCConvertValues(strMethod, strParams);
      
      // Execute
      value reply = CallRPC(strMethod, params);
      if(reply.type() != object_type) {
	throw runtime_error("invalid rpc reply");
      }
      
      // Parse reply
      const value& result = reply["result"];
      const value& error  = reply["error"];
      
      if (error.type() != null_type) {
	// Error
	stringstream errorStream;
	errorStream << error;
	strPrint = "error: " + errorStream.str();
	
	nRet = abs(error["code"].get_as<int>());
      } else {
	// Result
	if (result.type() == null_type) {
	  strPrint = "";
	} else if (result.type() == string_type) {
	  strPrint = result.get_as<std::string>();
	} else {
	  stringstream ss;
	  ss << result;
	  strPrint = ss.str();
	}
      }
    }
  catch (boost::thread_interrupted) {
    throw;
  }
  catch (std::exception& e) {
    strPrint = string("error: ") + e.what();
    nRet = 87;
  }
  catch (...) {
    PrintException(NULL, "CommandLineRPC()");
  }
  
  if (strPrint != "")
    {
      fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
  return nRet;
}




#ifdef TEST
int main(int argc, char *argv[])
{
#ifdef _MSC_VER
  // Turn off Microsoft heap dump noise
  _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  
  try
    {
      if (argc >= 2 && string(argv[1]) == "-server")
        {
	  printf("server ready\n");
	  ThreadRPCServer(NULL);
        }
      else
        {
	  return CommandLineRPC(argc, argv);
        }
    }
  catch (boost::thread_interrupted) {
    throw;
  }
  catch (std::exception& e) {
    PrintException(&e, "main()");
  } catch (...) {
    PrintException(NULL, "main()");
  }
  return 0;
}
#endif

const CRPCTable tableRPC;
