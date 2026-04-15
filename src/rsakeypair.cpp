#include "rsakeypair.h"
#include "base64.h"
#include "stringfunctions.h"

#include <mbedtls/bignum.h>
#include <mbedtls/md.h>

#include <cstring>
#include <vector>
#include <cmath>

RSAKeyPair::RSAKeyPair():m_initialized(false),m_oaep(false)
{
	mbedtls_entropy_init(&m_entropy);
	mbedtls_ctr_drbg_init(&m_ctr_drbg);
	// M9: Add personalisation string so each RNG domain produces independent output.
	static const unsigned char pers[] = "flip-rsakey-ctr-drbg-v1";
	mbedtls_ctr_drbg_seed(&m_ctr_drbg,mbedtls_entropy_func,&m_entropy,
	                       pers,sizeof(pers)-1);
}

RSAKeyPair::~RSAKeyPair()
{
	FreeContext();
	mbedtls_ctr_drbg_free(&m_ctr_drbg);
	mbedtls_entropy_free(&m_entropy);
}

const bool RSAKeyPair::Decrypt(const std::string &encrypted, std::string &message)
{
	if(m_initialized)
	{
		std::vector<std::string> encryptedparts;

		StringFunctions::Split(encrypted,"|",encryptedparts);
		message="";

		size_t rsa_len=mbedtls_rsa_get_len(&m_rsa);

		for(std::vector<std::string>::iterator i=encryptedparts.begin(); i!=encryptedparts.end(); i++)
		{
			std::vector<unsigned char> input;
			std::vector<unsigned char> output(rsa_len,0);
			size_t outputlength=output.size();
			Base64::Decode((*i),input);

			if(input.size()==rsa_len)
			{
				// mbedTLS 3.x: mode parameter (MBEDTLS_RSA_PRIVATE) removed.
				int rval=mbedtls_rsa_pkcs1_decrypt(&m_rsa,mbedtls_ctr_drbg_random,&m_ctr_drbg,&outputlength,&input[0],&output[0],output.size());

				// H1 backward-compat: if OAEP fails, retry with PKCS#1 v1.5 so
				// this node can still read messages sent by pre-H1 (unpatched)
				// FLIP peers that haven't upgraded yet.  Restore OAEP afterwards
				// so outbound encryption and future decrypts stay on the secure path.
				if(rval!=0 && m_oaep)
				{
					mbedtls_rsa_set_padding(&m_rsa,MBEDTLS_RSA_PKCS_V15,MBEDTLS_MD_NONE);
					outputlength=output.size();
					std::fill(output.begin(),output.end(),0);
					rval=mbedtls_rsa_pkcs1_decrypt(&m_rsa,mbedtls_ctr_drbg_random,&m_ctr_drbg,&outputlength,&input[0],&output[0],output.size());
					mbedtls_rsa_set_padding(&m_rsa,MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
				}

				if(rval==0)
				{
					if(outputlength<output.size())
					{
						output.erase(output.begin()+outputlength,output.end());
					}
					message+=std::string(output.begin(),output.end());
				}
				else
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		return true;
	}
	else
	{
		return false;
	}
}

const bool RSAKeyPair::Encrypt(const std::string &message, std::string &encrypted)
{
	if(m_initialized)
	{
		size_t rsa_len=mbedtls_rsa_get_len(&m_rsa);
		std::vector<unsigned char> output(rsa_len,0);
		// H1: blocksize depends on padding scheme in use.
		// OAEP/SHA-256 overhead = 2*hLen + 2 = 66 bytes (hLen=32 for SHA-256).
		// PKCS#1 v1.5 overhead = 11 bytes.
		// NOTE: switching to OAEP changes the wire format — old FLIP peers
		// (pre-H1) cannot decrypt OAEP-encrypted messages.  Use legacy=true
		// via SetFromEncodedPublicKey() to communicate with old peers.
		// mbedTLS 3.x: m_rsa.padding is opaque; use m_oaep flag instead.
		long blocksize = m_oaep
		                 ? (long)rsa_len - 66
		                 : (long)rsa_len - 11;
		std::string encryptedoutput("");
		std::string mess=message;
		std::vector<std::string> messageblocks;

		while(mess.size()>0)
		{
			if(mess.size()>blocksize)
			{
				messageblocks.push_back(mess.substr(0,blocksize));
				mess.erase(0,blocksize);
			}
			else
			{
				messageblocks.push_back(mess);
				mess.erase(0);
			}
		}

		for(std::vector<std::string>::iterator i=messageblocks.begin(); i!=messageblocks.end(); i++)
		{
			std::vector<unsigned char> input((*i).begin(),(*i).end());
			// mbedTLS 3.x: mode parameter (MBEDTLS_RSA_PUBLIC) removed.
			if(mbedtls_rsa_pkcs1_encrypt(&m_rsa,mbedtls_ctr_drbg_random,&m_ctr_drbg,input.size(),&input[0],&output[0])==0)
			{
				std::string temp("");
				Base64::Encode(output,temp);
				if(i!=messageblocks.begin())
				{
					encryptedoutput+="|";
				}
				encryptedoutput+=temp;
			}
			else
			{
				return false;
			}
		}

		encrypted=encryptedoutput;

		return true;

	}
	else
	{
		return false;
	}
}

void RSAKeyPair::FreeContext()
{
	if(m_initialized)
	{
		mbedtls_rsa_free(&m_rsa);
		m_initialized=false;
	}
}

const bool RSAKeyPair::Generate()
{
	InitializeContext();

	// C1: 3072 bits provides 128-bit security margin per NIST SP 800-57 rev5.
	// Old 1024-bit peers can still SEND messages to us (backward receive compat);
	// we warn the IRC user when such a message arrives — see ircserver.cpp.
	int rval=mbedtls_rsa_gen_key(&m_rsa,mbedtls_ctr_drbg_random,&m_ctr_drbg,3072,65537);

	if(rval!=0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

const std::string RSAKeyPair::GetEncodedPublicKey()
{
	if(m_initialized)
	{
		int rval=0;
		std::string lenstr("");
		std::string nencoded("");
		std::string eencoded("");

		// mbedTLS 3.x: export N and E via the MPI export API (struct is opaque).
		mbedtls_mpi N_mpi, E_mpi;
		mbedtls_mpi_init(&N_mpi);
		mbedtls_mpi_init(&E_mpi);

		rval=mbedtls_rsa_export(&m_rsa,&N_mpi,NULL,NULL,NULL,&E_mpi);

		std::vector<unsigned char> n(mbedtls_mpi_size(&N_mpi),0);
		std::vector<unsigned char> e(mbedtls_mpi_size(&E_mpi),0);

		rval|=mbedtls_mpi_write_binary(&N_mpi,&n[0],n.size());
		rval|=mbedtls_mpi_write_binary(&E_mpi,&e[0],e.size());

		mbedtls_mpi_free(&N_mpi);
		mbedtls_mpi_free(&E_mpi);

		Base64::Encode(n,nencoded);
		Base64::Encode(e,eencoded);

		// First field is the modulus byte count; mbedtls_rsa_get_len() replaces m_rsa.len.
		StringFunctions::Convert(mbedtls_rsa_get_len(&m_rsa),lenstr);

		return std::string(lenstr+"|"+nencoded+"|"+eencoded);
	}
	else
	{
		return std::string("");
	}
}

const std::string RSAKeyPair::GetEncodedPrivateKey()
{
	if(m_initialized)
	{
		// M10: local vectors hold raw key material; fill them with zeros before they
		// leave scope so key bytes do not linger in heap/stack memory.
		std::string dencoded("");
		std::string pencoded("");
		std::string qencoded("");
		std::string dpencoded("");
		std::string dqencoded("");
		std::string qpencoded("");

		// mbedTLS 3.x: export private key components via the MPI export API.
		mbedtls_mpi N_mpi, P_mpi, Q_mpi, D_mpi, E_mpi;
		mbedtls_mpi DP_mpi, DQ_mpi, QP_mpi;
		mbedtls_mpi_init(&N_mpi); mbedtls_mpi_init(&P_mpi); mbedtls_mpi_init(&Q_mpi);
		mbedtls_mpi_init(&D_mpi); mbedtls_mpi_init(&E_mpi);
		mbedtls_mpi_init(&DP_mpi); mbedtls_mpi_init(&DQ_mpi); mbedtls_mpi_init(&QP_mpi);

		mbedtls_rsa_export(&m_rsa,&N_mpi,&P_mpi,&Q_mpi,&D_mpi,&E_mpi);
		mbedtls_rsa_export_crt(&m_rsa,&DP_mpi,&DQ_mpi,&QP_mpi);

		std::vector<unsigned char> d(mbedtls_mpi_size(&D_mpi),0);
		std::vector<unsigned char> p(mbedtls_mpi_size(&P_mpi),0);
		std::vector<unsigned char> q(mbedtls_mpi_size(&Q_mpi),0);
		std::vector<unsigned char> dp(mbedtls_mpi_size(&DP_mpi),0);
		std::vector<unsigned char> dq(mbedtls_mpi_size(&DQ_mpi),0);
		std::vector<unsigned char> qp(mbedtls_mpi_size(&QP_mpi),0);

		mbedtls_mpi_write_binary(&D_mpi,&d[0],d.size());
		mbedtls_mpi_write_binary(&P_mpi,&p[0],p.size());
		mbedtls_mpi_write_binary(&Q_mpi,&q[0],q.size());
		mbedtls_mpi_write_binary(&DP_mpi,&dp[0],dp.size());
		mbedtls_mpi_write_binary(&DQ_mpi,&dq[0],dq.size());
		mbedtls_mpi_write_binary(&QP_mpi,&qp[0],qp.size());

		mbedtls_mpi_free(&N_mpi); mbedtls_mpi_free(&P_mpi); mbedtls_mpi_free(&Q_mpi);
		mbedtls_mpi_free(&D_mpi); mbedtls_mpi_free(&E_mpi);
		mbedtls_mpi_free(&DP_mpi); mbedtls_mpi_free(&DQ_mpi); mbedtls_mpi_free(&QP_mpi);

		Base64::Encode(d,dencoded);
		Base64::Encode(p,pencoded);
		Base64::Encode(q,qencoded);
		Base64::Encode(dp,dpencoded);
		Base64::Encode(dq,dqencoded);
		Base64::Encode(qp,qpencoded);

		// Zeroize raw key material now that it has been encoded.
		std::fill(d.begin(),  d.end(),  0);
		std::fill(p.begin(),  p.end(),  0);
		std::fill(q.begin(),  q.end(),  0);
		std::fill(dp.begin(), dp.end(), 0);
		std::fill(dq.begin(), dq.end(), 0);
		std::fill(qp.begin(), qp.end(), 0);

		return std::string(GetEncodedPublicKey()+"|"+dencoded+"|"+pencoded+"|"+qencoded+"|"+dpencoded+"|"+dqencoded+"|"+qpencoded);
	}
	else
	{
		return std::string("");
	}
}


void RSAKeyPair::InitializeContext()
{
	FreeContext();

	// H1: OAEP (PKCS#1 v2.1) with SHA-256 eliminates Bleichenbacher oracle attack.
	// mbedTLS 3.x: init takes no padding args; use mbedtls_rsa_set_padding() separately.
	mbedtls_rsa_init(&m_rsa);
	mbedtls_rsa_set_padding(&m_rsa,MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	m_oaep=true;
	m_initialized=true;
}

void RSAKeyPair::InitializeLegacyContext()
{
	FreeContext();
	// H1-legacy: PKCS#1 v1.5 used only when communicating with pre-H1 peers.
	// The /1024 IRC command sets this mode for a specific peer; /4096 resets.
	mbedtls_rsa_init(&m_rsa);
	mbedtls_rsa_set_padding(&m_rsa,MBEDTLS_RSA_PKCS_V15,MBEDTLS_MD_NONE);
	m_oaep=false;
	m_initialized=true;
}

const bool RSAKeyPair::SetFromEncodedPublicKey(const std::string &publickey, bool legacy)
{
	// H1: use legacy PKCS#1 v1.5 context when communicating with old FLIP peers.
	legacy ? InitializeLegacyContext() : InitializeContext();
	std::vector<std::string> keyparts;

	StringFunctions::Split(publickey,"|",keyparts);

	if(keyparts.size()==3)
	{
		std::vector<unsigned char> n;
		std::vector<unsigned char> e;

		// keyparts[0] is the stored modulus byte count; the actual length is
		// authoritative from the imported key, so we just discard keyparts[0].
		Base64::Decode(keyparts[1],n);
		Base64::Decode(keyparts[2],e);

		// mbedTLS 3.x: use mbedtls_rsa_import_raw() + mbedtls_rsa_complete()
		// instead of writing directly into m_rsa.N / m_rsa.E.
		mbedtls_rsa_import_raw(&m_rsa,&n[0],n.size(),NULL,0,NULL,0,NULL,0,&e[0],e.size());
		mbedtls_rsa_complete(&m_rsa);

		if(mbedtls_rsa_check_pubkey(&m_rsa)==0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}

}

const bool RSAKeyPair::SetFromEncodedPrivateKey(const std::string &privatekey)
{
	InitializeContext();
	std::vector<std::string> keyparts;

	StringFunctions::Split(privatekey,"|",keyparts);

	if(keyparts.size()==9)
	{
		if(SetFromEncodedPublicKey(keyparts[0]+"|"+keyparts[1]+"|"+keyparts[2])==true)
		{
			std::vector<unsigned char> d;
			std::vector<unsigned char> p;
			std::vector<unsigned char> q;

			Base64::Decode(keyparts[3],d);
			Base64::Decode(keyparts[4],p);
			Base64::Decode(keyparts[5],q);
			// keyparts[6..8] are DP, DQ, QP — mbedtls_rsa_complete() recomputes
			// them from P, Q, D so we do not need to import them separately.

			// mbedTLS 3.x: import_raw accumulates; N+E already set by
			// SetFromEncodedPublicKey above.  Add D, P, Q then complete.
			mbedtls_rsa_import_raw(&m_rsa,NULL,0,&p[0],p.size(),&q[0],q.size(),&d[0],d.size(),NULL,0);
			mbedtls_rsa_complete(&m_rsa);

			if(mbedtls_rsa_check_privkey(&m_rsa)==0)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}

}

// C1: Parse the first field of an encoded public key (which is the modulus
// byte count) and return the key size in bits.  Used by ircserver to warn users when
// a peer's key is too small (< 2048 bits).  Returns 0 on parse failure.
int RSAKeyPair::GetKeyBitsFromEncodedKey(const std::string &encodedkey)
{
	if(encodedkey.empty())
	{
		return 0;
	}
	std::string::size_type pos=encodedkey.find('|');
	std::string lenstr=(pos==std::string::npos) ? encodedkey : encodedkey.substr(0,pos);
	int lenbytes=0;
	StringFunctions::Convert(lenstr,lenbytes);
	if(lenbytes<=0)
	{
		return 0;
	}
	return lenbytes*8;
}
