#include "client-server.hpp"

SCENARIO("Hash", "[getHash]"){
  getHash("testfile.txt");
  getHash("same_testfile.txt");
  REQUIRE(hash_to_string("testfile.txt.hash") == hash_to_string("same_testfile.txt.hash));
}
