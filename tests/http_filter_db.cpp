#include "db.h"
#include "streams.h"

#include <assert.h>
#include <stdio.h>

bool fTestNet = false;

int main() {
  CAddrDb db;
  const CService peer("8.8.8.8", GetDefaultPort());
  db.Add(CAddress(peer), true);
  db.Good(peer, REQUIRE_VERSION, "/test/", GetRequireHeight(), NODE_NETWORK);

  bool nets[NET_MAX] = {};
  nets[NET_IPV4] = true;
  std::set<CNetAddr> ips;
  CAddrDb untested;
  untested.Add(CAddress(peer), true);
  untested.SetFilterHttp(true);
  untested.GetIPs(ips, NODE_NETWORK, 1000, nets);
  assert(ips.empty()); // Untested peers must not be published.

  db.GetIPs(ips, NODE_NETWORK, 1000, nets);
  assert(ips.count(peer) == 1);

  db.SetFilterHttp(true);
  ips.clear();
  db.GetIPs(ips, NODE_NETWORK, 1000, nets);
  assert(ips.empty()); // An unchecked peer cannot be published.

  db.Good(peer, REQUIRE_VERSION, "/test/", GetRequireHeight(), NODE_NETWORK, true, false);
  db.GetIPs(ips, NODE_NETWORK, 1000, nets);
  assert(ips.count(peer) == 1);

  db.Good(peer, REQUIRE_VERSION, "/test/", GetRequireHeight(), NODE_NETWORK, true, true);
  ips.clear();
  db.GetIPs(ips, NODE_NETWORK, 1000, nets);
  assert(ips.empty());

  db.SetFilterHttp(false);
  db.GetIPs(ips, NODE_NETWORK, 1000, nets);
  assert(ips.count(peer) == 1); // Bitcoin eligibility was not changed.

  CAddrDb persisted;
  persisted.Add(CAddress(peer), true);
  persisted.Good(peer, REQUIRE_VERSION, "/test/", GetRequireHeight(), NODE_NETWORK, true, true);
  DataStream saved;
  saved << persisted;
  CAddrDb restored;
  restored.SetFilterHttp(true);
  saved >> restored;
  ips.clear();
  restored.GetIPs(ips, NODE_NETWORK, 1000, nets);
  assert(ips.empty()); // The excluded result survives a restart.
  restored.SetFilterHttp(false);
  restored.GetIPs(ips, NODE_NETWORK, 1000, nets);
  assert(ips.count(peer) == 1);

  puts("HTTP DNS filter: untested, unchecked, closed, open, disabled, and persisted checks passed");
}
