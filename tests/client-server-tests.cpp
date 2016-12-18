#include <webdav/client-server.hpp>
#include "stdafx.h"
#include <map>
#include "catch.hpp"

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

SCENARIO("upload", "[upload]"){
	std::map<std::string, std::string> options =
	{
		{ "webdav_hostname", "https://webdav.yandex.ru" },
		{ "webdav_login", "hitode221" },
		{ "webdav_password", "m160802" }
	};
	std::unique_ptr<WebDAV::Client> client(WebDAV::Client::Init(options));
	upload_to_disk_root("upload", client);
}
