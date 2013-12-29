#define BOOST_TEST_MODULE Litecoin Test Suite
#define BOOST_TEST_AUTO_START_DBG
#include <boost/test/unit_test.hpp>

#include "config.h"
#include <boost/filesystem.hpp>

#include "db.h"
#include "txdb.h"
#include "main.h"
#include "wallet.h"
#include "util.h"

CWallet* pwalletMain;
CClientUIInterface uiInterface;

extern bool fPrintToConsole;
extern void noui_connect();

namespace fs = boost::filesystem;

struct TestingSetup {
    CCoinsViewDB *pcoinsdbview;
    fs::path pathTemp;
    boost::thread_group threadGroup;
  
  TestingSetup() {

    pathTemp = GetTempPath() / strprintf("test_litecoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
    fs::create_directories(pathTemp);

    char *argv[] = {
      "test_trollcoin"
      , "--debug", "true"
      , "--datadir", const_cast<char*>(pathTemp.string().c_str())
      , "--testnet", "true"
    };
    config_init(7, argv);

    noui_connect();
    bitdb.MakeMock();

    pblocktree = new CBlockTreeDB(pathTemp
				  , 1 << 20
				  , true);
    pcoinsdbview = new CCoinsViewDB(pathTemp, 1 << 23, true);
    pcoinsTip = new CCoinsViewCache(*pcoinsdbview);
    LoadBlockIndex();
    InitBlockIndex();
    bool fFirstRun;
    pwalletMain = new CWallet("wallet.dat");
    pwalletMain->LoadWallet(fFirstRun);
    RegisterWallet(pwalletMain);
    nScriptCheckThreads = 3;
    for (int i=0; i < nScriptCheckThreads-1; i++)
      threadGroup.create_thread(&ThreadScriptCheck);
  }
  ~TestingSetup()
  {
    threadGroup.interrupt_all();
    threadGroup.join_all();
    delete pwalletMain;
    pwalletMain = NULL;
    delete pcoinsTip;
    delete pcoinsdbview;
    delete pblocktree;
    bitdb.Flush(true);
    fs::remove_all(pathTemp);
  }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);

void Shutdown(void* parg)
{
  exit(0);
}

void StartShutdown()
{
  exit(0);
}

