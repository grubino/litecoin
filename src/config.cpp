#include "config.h"
#include "util.h"
#include <boost/filesystem.hpp>
#include <string>

namespace po = boost::program_options;
namespace fs = boost::filesystem;
using namespace std;

po::variables_map user_options;
po::options_description gen_opts("General Options");
po::options_description config_opts("Config");
po::options_description opts("Options");
po::positional_options_description pos_opts;

static const unsigned int DEFAULT_DATABASE_CACHE_SIZE = 25;
static const unsigned int DEFAULT_CONNECTION_TIMEOUT = 5000;
static const unsigned int DEFAULT_SOCKS_VERSION = 5;

void config_init(int argc, char** argv) {
  gen_opts.add_options()
    ("version,v", "print version info")
    ("help,?", "produce help message")
    ("datadir", po::value<fs::path>()->default_value(GetDefaultDataDir()), "Specify data directory")
    ("conf", po::value<fs::path>()->default_value(fs::path("trollcoin.conf")), "Specify configuration file (default: trollcoin.conf)")
    ("pid", po::value<fs::path>()->default_value(fs::path("trollcoin.pid")), "Specify pid file (default: trollcoind.pid)")
    ("gen", po::value<bool>()->implicit_value(true)->default_value(false), "Generate coins (default: false)")
    ("dbcache", po::value<unsigned int>()->default_value(DEFAULT_DATABASE_CACHE_SIZE), "Set database cache size in megabytes (default: 25)")
    ("timeout", po::value<unsigned int>()->default_value(DEFAULT_CONNECTION_TIMEOUT), "Specify connection timeout in milliseconds (default: 5000)")
    ("proxy", po::value<string>(), "Specify socks proxy")
    ("socks", po::value<unsigned int>()->default_value(DEFAULT_SOCKS_VERSION), "Select the version of socks proxy to use (4-5, default: 5)")
    ("tor", po::value<string>(), "Use proxy to reach tor hidden services (default: same as -proxy)")
    ("dns", po::value<bool>()->implicit_value(true)->default_value(true), "Allow DNS lookups for --addnode, --seednode and --connect")
    ("port", po::value<unsigned int>()->default_value(9333), "Listen for connections on <port> (default: 9333 or testnet: 19333)")
    ("maxconnections", po::value<unsigned int>()->default_value(125), "Maintain at most <n> connections to peers (default: 125)")
    ("addnode", po::value<string>(), "Add a node to connect to and attempt to keep the connection open")
    ("connect", po::value<string>(), "Connect only to the specified node(s)")
    ("seednode"
     , po::value<string>()->default_value("")
     , "Connect to a node to retrieve peer addresses, and disconnect")
    ("externalip", po::value<string>(), "Specify your own public address")
    ("onlynet", po::value< vector<string> >()->composing(), "Only connect to nodes in network <net> (IPv4, IPv6 or Tor)")
    ("discover", po::value<bool>()->implicit_value(true)->default_value(true), "Discover own IP address (default: true when listening and false --externalip)")
    ("checkpoints"
     , po::value<bool>()->implicit_value(true)->default_value(true)
     , "Only accept block chain matching built-in checkpoints (default: true)")
    ("listen", po::value<bool>()->implicit_value(true), "Accept connections from outside (default: true if no --proxy or --connect)")
    ("bind", po::value<string>(), "Bind to given address and always listen on it. Use [host]:port notation for IPv6")
    ("dnsseed", po::value<bool>()->implicit_value(true), "Find peers using DNS lookup (default: true unless --connect)")
    ("banscore", po::value<unsigned int>()->default_value(100), "Threshold for disconnecting misbehaving peers (default: 100)")
    ("bantime"
     , po::value<unsigned int>()->default_value(86400)
     , "Number of seconds to keep misbehaving peers from reconnecting (default: 86400)")
    ("maxreceivebuffer"
     , po::value<unsigned int>()->default_value(5000)
     , "Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)")
    ("maxsendbuffer", po::value<unsigned int>()->default_value(1000), "Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)")
    ("bloomfilters", po::value<bool>()->implicit_value(true)->default_value(true), "Allow peers to set bloom filters (default: true)")
#ifdef USE_UPNP
#if USE_UPNP
    ("upnp", po::value<bool>()->implicit_value(true)->default_value(true), "Use UPnP to map the listening port (default: true when listening)")
#else
    ("upnp", po::value<bool>()->implicit_value(true)->default_value(false), "Use UPnP to map the listening port (default: false)")
#endif
#endif
    ("paytxfee", po::value<string>(), "Fee per KB to add to transactions you send")
    ("minrelaytxfee", po::value<string>(), "Fee per KB to charge for transactions you relay")
    ("mintxfee", po::value<string>(), "Fee per KB to charge for transactions")
    ("mininput", po::value<string>(), "When creating transactions, ignore inputs with value less than this (default: 0.0001)")
#ifdef QT_GUI
    ("server", po::value<bool>()->implicit_value(true)->default_value(true), "Accept command line and JSON-RPC commands")
#endif
#if !defined(WIN32) && !defined(QT_GUI)
    ("daemon", po::value<bool>()->implicit_value(true)->default_value(false), "Run in the background as a daemon and accept commands")
#endif
    ("testnet", po::value<bool>()->implicit_value(true)->default_value(false), "Use the test network")
    ("debug", po::value<bool>()->implicit_value(true)->default_value(false), "Output extra debugging information. Implies all other --debug* options")
    ("debugnet", po::value<bool>()->implicit_value(true)->default_value(false), "Output extra network debugging information")
    ("logtimestamps", po::value<bool>()->implicit_value(true)->default_value(true), "Prepend debug output with timestamp (default: true)")
    ("shrinkdebugfile", po::value<bool>()->implicit_value(true)->default_value(true), "Shrink debug.log file on client startup (default: true)")
    ("printtoconsole", po::value<bool>()->implicit_value(true)->default_value(true), "Send trace/debug info to console instead of debug.log file")
    ("printblock", po::value<string>(), "print block identified by has")
    ("printblocktree", po::value<bool>()->implicit_value(true)->default_value(false), "print block tree")
#ifdef WIN32
    ("printtodebugger", po::value<bool>()->implicit_value(true)->default_value(false), "Send trace/debug info to debugger")
#endif
    ("rpcuser", po::value<string>(), "Username for JSON-RPC connections")
    ("rpcpassword", po::value<string>(), "Password for JSON-RPC connections")
    ("rpcport"
     , po::value<unsigned int>()->default_value(9332)
     , "Listen for JSON-RPC connections on <port> (default: 9332 or testnet: 19332)")
    ("rpcallowip", po::value< vector<string> >()->composing(), "Allow JSON-RPC connections from specified IP address")
#ifndef QT_GUI
    ("rpcconnect", po::value<string>(), "Send commands to node running on <ip> (default: 127.0.0.1)")
#endif
    ("rpcthreads", po::value<unsigned int>()->default_value(4), "Set the number of threads to service RPC calls (default: 4)")
    ("blocknotify", po::value<string>(), "Execute command when the best block changes (%s in cmd is replaced by block hash)")
    ("walletnotify", po::value<string>(), "Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)")
    ("alertnotify", po::value<string>(), "Execute command when a relevant alert is received (%s in cmd is replaced by message)")
    ("upgradewallet", po::value<bool>()->implicit_value(true)->default_value(false), "Upgrade wallet to latest format")
    ("keypool", po::value<unsigned int>()->default_value(100), "Set key pool size to <n> (default: 100)")
    ("rescan", po::value<bool>()->implicit_value(true)->default_value(false), "Rescan the block chain for missing wallet transactions")
    ("salvagewallet", po::value<bool>()->implicit_value(true)->default_value(false), "Attempt to recover private keys from a corrupt wallet.dat")
    ("checkblocks", po::value<int>()->default_value(288), "How many blocks to check at startup (default: 288, 0 = all)")
    ("checklevel", po::value<int>()->default_value(3), "How thorough the block verification is (0-4, default: 3)")
    ("genproclimit", po::value<int>()->default_value(-1), "How many threads to start (default: -1)")
    ("txindex", po::value<bool>()->implicit_value(true)->default_value(false), "Maintain a full transaction index (default: false)")
    ("loadblock", po::value<fs::path>(), "Imports blocks from external blk000??.dat file")
    ("reindex", po::value<bool>()->implicit_value(true)->default_value(false), "Rebuild block chain index from current blk000??.dat files")
    ("par"
     , po::value<unsigned int>()->default_value(0)
     , "Set the number of script verification threads (up to 16, 0 = auto, <0 = leave that many cores free, default: 0)")
    ;
  
  po::options_description block_creation_opts("Block Creation Options");
  block_creation_opts.add_options()
    ("blockminsize", po::value<unsigned int>()->default_value(0), "Set minimum block size in bytes (default: 0)")
    ("blockmaxsize", po::value<unsigned int>()->default_value(250000), "Set maximum block size in bytes (default: 250000)")
    ("blockprioritysize"
     , po::value<unsigned int>()->default_value(27000)
     , "Set maximum size of high-priority/low-fee transactions in bytes (default: 27000)")
    ;
  
  po::options_description ssl_opts("SSL Options");
  ssl_opts.add_options()
    ("rpcssl", po::value<bool>()->implicit_value(true)->default_value(true), "Use OpenSSL (https) for JSON-RPC connections")
    ("rpcsslcertificatechainfile"
     , po::value<fs::path>()->default_value(fs::path("server.cert"))
     , "Server certificate file (default: server.cert)")
    ("rpcsslprivatekeyfile", po::value<fs::path>()->default_value(fs::path("server.cert")), "Server private key (default: server.pem)")
    ("rpcsslciphers"
     , po::value<string>()->default_value("TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH")
     , "Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)")
    ;
  
  pos_opts.add("command", 1);
  pos_opts.add("params", -1);
  
  opts.add(gen_opts).add(block_creation_opts).add(ssl_opts);
  
  config_opts.add(opts);
  
  po::store(po::command_line_parser(argc, argv)
	    .options(opts).positional(pos_opts).run(), user_options);
  po::notify(user_options);

  if(user_options.count("conf") and fs::exists(user_options["conf"].as<fs::path>())) {
    po::store(po::parse_config_file<char>(user_options["conf"].as<fs::path>().string().c_str(), config_opts), user_options);
  } else if(user_options.count("conf")) {
    std::cerr 
      << "couldn't find configuration file: " 
      << user_options["conf"].as<fs::path>() 
      << ", configuration from file skipped." << std::endl;
  }
  po::notify(user_options);
    
}
