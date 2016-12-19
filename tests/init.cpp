
#include <webdav/Clie.hpp>
#include "catch.hpp"

SCENARIO("upload", "[U]"){
	UtoD();
	Info inf("conf.txt");
	std::map<std::string, std::string> options =
	{
		{ "webdav_hostname", inf.url_.c_str() },
		{ "webdav_login",    inf.login_.c_str() },
		{ "webdav_password", inf.password_.c_str() }
	};
	std::unique_ptr<WebDAV::Client> client(WebDAV::Client::Init(options));
	REQUIRE(client->check("/path/f1.txt.aes"));
	REQUIRE(client->check("/path/1/"));
	REQUIRE(client->check("/path/1/f2.txt.aes"));
	REQUIRE(client->check("/path/1/3/"));
	REQUIRE(client->check("/path/1/3/f3.txt.aes"));
	REQUIRE(client->check("/path/1/3/f4.txt.aes"));
	REQUIRE(client->check("/path/2/"));
	REQUIRE(client->check("/path/2/f2.txt.aes"));
}

SCENARIO("download", "[D]"){
	DfromD();	
}
