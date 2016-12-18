#include <webdav/client-server.hpp>
#include "stdafx.h"
#include <map>
#include <unistd.h>  
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
	REQUIRE(client->check("1.txt"));
	REQUIRE(client->check("2.txt"));
	REQUIRE(client->check("dir/"));
	REQUIRE(client->check("dir/3.txt"));
	REQUIRE(client->check("dir/dir_in/"));
	REQUIRE(client->check("dir/dir_in/4.txt"));
}

SCENARIO("download", "[download]"){
	 std::map<std::string, std::string> options =
	{
		{ "webdav_hostname", "https://webdav.yandex.ru" },
		{ "webdav_login", "hitode221" },
		{ "webdav_password", "m160802" }
	};
	std::unique_ptr<WebDAV::Client> client(WebDAV::Client::Init(options));
	download_from_disk_root("download", client);
	REQUIRE(!client->check("1.txt"));
	_chdir("download");
	REQUIRE(boost::filesystem::is_regular_file(boost::filesystem::system_complete("1.txt")));
}
