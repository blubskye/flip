#ifndef _ircserver_
#define _ircserver_

#include "../ilogger.h"
#include "../idatabase.h"
#include "../flipeventsource.h"
#include "../flipeventhandler.h"
#include "../datetime.h"
#include "../stringfunctions.h"
#include "ircclientconnection.h"
#include "irccommandhandler.h"
#include "ircchannel.h"
#include "ircflipservice.h"

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <vector>
#include <set>
#include <map>

class IRCServer:public IRCCommandHandler,public FLIPEventSource,public FLIPEventHandler,public ILogger,public IDatabase
{
public:
	IRCServer();
	~IRCServer();

	void Start();
	void Shutdown();
	void Update(const unsigned long ms);

	const bool HandleCommand(const IRCCommand &command, IRCClientConnection *client);

	const bool HandleFLIPEvent(const FLIPEvent &flipevent);

private:

	enum MessageType
	{
		MT_MESSAGE=1,
		MT_NOTICE
	};

	void SendChannelMessageToClients(const int identityid, const std::string &channel, const std::string &message, const MessageType messagetype);
	void SendTopicToClients(const int identityid, const std::string &channel, const std::string &topic);
	void SendPrivateMessageToClients(const int identityid, const std::string &recipient, const std::string &encryptedmessage, const MessageType messagetype);
	void SendJoinMessageToClients(const int identityid, const std::string &channel);
	void SendPartMessageToClients(const int identityid, const std::string &channel);
	void SendNickChangeMessageToClients(const int identityid, const std::string &oldnick);
	void SendMOTDLines(IRCClientConnection *client);

	void ProcessFLIPEvent(const int identityid, const FLIPEvent &flipevent);
	const bool SetupServerSSL();
	void ShutdownServerSSL();
	const bool SetupClientSSL(IRCClientConnection::ssl_client_info &ssl, int socket);
	void ReloadMOTD();
	const bool NickInUse(IRCClientConnection *client, const std::string &nick, const bool clientsonly) const;
	void FindAndResolveNickCollision(const int identityid, const std::string &newnick, const bool notifyclients);

	const bool GetPeerDBID(IRCClientConnection *client);
	void GetPublicKey(IRCClientConnection *client);
	IRCChannel* GetChannel(const std::string&);
	void dbAddChannel(IRCChannel* chan) const;
	void dbUpdateChannel(IRCChannel* chan) const;
	void dbInitChannels();

	void LoadIdentity(const int identityid);
	const bool GetIdentityIDFromNick(const std::string &nick, int &identityid) const;
	const bool GetIdentityIDFromSSK(const std::string &ssk, int &identityid) const;
	const bool ValidateIdentity(const int identityid);
	const bool InvalidateIdentity(const int identityid);

	const bool IdentityConnectedAsClient(const int identityid) const;

	struct idinfo
	{
		idinfo():m_identityid(-1),m_basenickcollided(false),m_pubkeynickcollided(false),m_pubkeynickok(false),m_dbidnickok(false),m_validated(false),m_legacycompat(false)		{ }

		struct messagequeueitem
		{
			messagequeueitem(const FLIPEvent &message, const int edition, const DateTime &insertday, const DateTime &arrivaltime):m_message(message),m_edition(edition),m_insertday(insertday),m_arrivaltime(arrivaltime)	{}
			FLIPEvent m_message;
			int m_edition;
			DateTime m_insertday;
			DateTime m_arrivaltime;
		};

		// custom comparator so messages are sorted by earliest messages first
		class messagequeuecompare
		{
		public:
			bool operator()(const messagequeueitem &lhs, const messagequeueitem &rhs) const
			{
				return ( (lhs.m_insertday<rhs.m_insertday) || (lhs.m_insertday==rhs.m_insertday && lhs.m_edition<rhs.m_edition) || (lhs.m_insertday==rhs.m_insertday && lhs.m_edition==rhs.m_edition && lhs.m_message<rhs.m_message) );
			}
		};

		void SetNick(const std::string &nick)
		{
			m_basenick=nick;
			BuildPubKeyNick();
			BuildDBIDNick();
		}

		const std::string GetNick() const
		{
			if(m_basenickcollided==false)
			{
				return m_basenick;
			}
			else if(m_pubkeynickcollided==false)
			{
				return m_pubkeynick;
			}
			else
			{
				return m_dbidnick;
			}
		}

		const bool ProgressNickCollision()
		{
			if(m_basenickcollided==false)
			{
				SetBaseNickCollided(true);
				return true;
			}
			if(m_pubkeynickcollided==false)
			{
				SetPubKeyNickCollided(true);
				return true;
			}
			return false;
		}

		void ClearNickCollided()
		{
			SetBaseNickCollided(false);
			SetPubKeyNickCollided(false);
		}

		void SetBaseNickCollided(const bool collided)
		{
			m_basenickcollided=collided;
			m_pubkeynickok=false;
			m_dbidnickok=false;
			BuildPubKeyNick();
		}

		void SetPubKeyNickCollided(const bool collided)
		{
			m_pubkeynickcollided=collided;
			m_pubkeynickok=false;
			m_dbidnickok=false;
			BuildPubKeyNick();
			BuildDBIDNick();
		}

		const std::string GetIRCUser() const
		{
			/*
			RFC 2812 - 2.3.1
			  user       =  1*( %x01-09 / %x0B-0C / %x0E-1F / %x21-3F / %x41-FF )
                  ; any octet except NUL, CR, LF, " " and "@"
			*/
			std::string ircuser=StringFunctions::Replace(m_publickey,"@","_");
			return ircuser;
		}

		//std::string m_nick;
		int m_identityid;
		std::string m_basenick;
		bool m_basenickcollided;
		bool m_pubkeynickcollided;
		std::string m_publickey;
		std::map<DateTime,int> m_lastdayedition;	// map of day, and edition # that we already processed from the identity - messages more than +1 after the last edition will be queued
		std::set<messagequeueitem,messagequeuecompare> m_messagequeue;
		DateTime m_lastircactivity;
		bool m_validated;
		// C1/H1-compat: true = use PKCS#1 v1.5 when SENDING to this peer.
		// Set by IRC command "/1024 <nick>", cleared by "/4096 <nick>".
		// The server warns the local user on receive when this peer's key is < 2048 bits.
		bool m_legacycompat;

	private:
		bool m_pubkeynickok;
		bool m_dbidnickok;
		std::string m_pubkeynick;
		std::string m_dbidnick;

		void BuildPubKeyNick()
		{
			m_pubkeynick=m_basenick+"_";

			std::vector<std::string> keyparts;
			StringFunctions::Split(m_publickey,"@",keyparts);
			if(keyparts.size()>1)
			{
				// replace ~ in key with _ to conform to IRC acceptable nick characters
				keyparts[1]=StringFunctions::Replace(keyparts[1],"~","_");
				m_pubkeynick+=keyparts[1].substr(0,5);
			}

			m_pubkeynickok=true;
		}

		void BuildDBIDNick()
		{
			BuildPubKeyNick();
			m_dbidnick=m_pubkeynick;

			std::string idstr("");
			StringFunctions::Convert(m_identityid,idstr);

			m_dbidnick+="_"+idstr;

			m_dbidnickok=true;
		}
	};

	DateTime m_datestarted;
	std::vector<int> m_listensockets;				// sockets we are listening on
	std::vector<int> m_ssllistensockets;			// SSL sockets we are listening on
	std::vector<IRCClientConnection *> m_clients;
	std::string m_servername;
	std::string m_flipservicenick;
	IRCFLIPService m_flipservice;

	std::map<int,idinfo> m_ids;
	std::map<std::string,std::set<int> > m_idchannels;	// channels each id is in
	std::set<int> m_idhassent;							// contains id if that identity has already sent a message within the window - we will accept all messages after no matter when they were sent
	std::map<std::string, IRCChannel*> m_channels;					// known channels

	// H1-compat: channels where all members use legacy (PKCS#1 v1.5) encryption.
	// Set by /legacy #channel, cleared by /modern #channel.  Any identity that
	// joins a channel in this set automatically gets m_legacycompat=true.
	std::set<std::string> m_legacychannels;

	std::vector<std::string> m_motdlines;

	// C9: maximum simultaneous IRC client connections (from IRCMaxClients option).
	int m_maxclients;

	// C10: server password (from IRCPassword option).  Empty = no auth required.
	// Clients must send PASS <password> before NICK/USER when this is non-empty.
	std::string m_ircpassword;

	struct ssl_server_info
	{
		mbedtls_x509_crt m_cert;
		mbedtls_pk_context m_pk;
		// mbedTLS 3.x: mbedtls_pk_parse_key needs an RNG for password-protected keys.
		mbedtls_entropy_context m_entropy;
		mbedtls_ctr_drbg_context m_ctr_drbg;
	};
	ssl_server_info m_ssl;
	bool m_sslsetup;

	#ifdef _WIN32
	static bool m_wsastartup;
	#endif

};

#endif	// _ircserver_
