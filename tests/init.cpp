#include <webdav/client.hpp>
#include <webdav/Clie.hpp>
#include "catch.hpp"

SCENARIO("upload", "[upload]"){
	UtoDisk();
	/*REQUIRE(client->check("1.txt"));
	REQUIRE(client->check("2.txt"));
	REQUIRE(client->check("dir/"));
	REQUIRE(client->check("dir/3.txt"));
	REQUIRE(client->check("dir/dir_in/"));
	REQUIRE(client->check("dir/dir_in/4.txt"));*/
}

SCENARIO("download", "[download]"){
	DfromD();	
}
