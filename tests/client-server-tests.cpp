#include <webdav/client-server.hpp>

SCENARIO("Hash", "[getHash]"){
  getHash("testfile.txt");
  getHash("same_testfile.txt");
  REQUIRE(hash_to_string("testfile.txt.hash") == hash_to_string("same_testfile.txt.hash"));
}

SCENARIO("crypt", "[crypt]"){
  encrypt("testfile.txt", "en_testfile.txt");
  decrypt("en_testfile.txt", "de_testfile.txt");
  std::ifstream expected("testfile.txt");
	std::ifstream output("de_testfile.txt");
	std::string first, second;
	
	bool flag = true;

	while (expected || output) {
		std::getline(expected, first);
		std::getline(output, second);
		if (first != second) {
			flag = false;
			break;
		}
	}
  REQUIRE(flag);
}
