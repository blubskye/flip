#ifndef _rsakeypair_
#define _rsakeypair_

#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <string>

class RSAKeyPair
{
public:
	RSAKeyPair();
	~RSAKeyPair();

	const bool Generate();

	// H1: legacy=true selects PKCS#1 v1.5 padding for compatibility with
	// pre-H1 FLIP peers.  Default (false) uses OAEP/SHA-256.
	const bool SetFromEncodedPublicKey(const std::string &publickey, bool legacy=false);
	const bool SetFromEncodedPrivateKey(const std::string &privatekey);

	const std::string GetEncodedPublicKey();
	const std::string GetEncodedPrivateKey();

	const bool Encrypt(const std::string &message, std::string &encrypted);
	const bool Decrypt(const std::string &encrypted, std::string &message);

	// C1: Parse modulus byte count from the first field of an encoded public
	// key and return the key size in bits.  Returns 0 on parse failure.
	static int GetKeyBitsFromEncodedKey(const std::string &encodedkey);

private:
	void InitializeContext();
	// H1: Legacy context uses PKCS#1 v1.5 (V15) for sending to old peers.
	void InitializeLegacyContext();
	void FreeContext();

	mbedtls_entropy_context m_entropy;
	mbedtls_ctr_drbg_context m_ctr_drbg;
	mbedtls_rsa_context m_rsa;
	bool m_initialized;
	// mbedTLS 3.x: m_rsa.padding is opaque; track the scheme ourselves.
	bool m_oaep;

};

#endif	// _rsakeypair_
