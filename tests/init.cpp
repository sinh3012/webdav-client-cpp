
#include <webdav/Clie.hpp>
#include "catch.hpp"

SCENARIO("upload", "[U]"){
	UtoD();
	REQUIRE(client->check("/path/f1.txt"));
	REQUIRE(client->check("/path/1/"));
	REQUIRE(client->check("/path/1/f2.txt"));
	REQUIRE(client->check("/path/1/3/"));
	REQUIRE(client->check("/path/1/3/f3.txt"));
	REQUIRE(client->check("/path/1/3/f4.txt"));
	REQUIRE(client->check("/path/2/"));
	REQUIRE(client->check("/path/2/f2.txt"));
}

/*SCENARIO("download", "[D]"){
	DfromD();	
}
*/
