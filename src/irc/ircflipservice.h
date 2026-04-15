#ifndef _ircflipservice_
#define _ircflipservice_

#include <functional>

#include "../ilogger.h"
#include "../idatabase.h"
#include "irccommandhandler.h"
#include "ircclientconnection.h"

class IRCFLIPService:public IRCCommandHandler,public ILogger,public IDatabase
{
public:
	IRCFLIPService();

	void SetNick(const std::string &nick);

	const bool HandleCommand(const IRCCommand &command, IRCClientConnection *client);
	void SendHelp(IRCClientConnection *client, const std::string &command);

	void SetConnected(const bool connected)		{ m_connected=connected; }
	void SetGetIdentityFunctions(std::function<const bool(const std::string &,int &)> idfromnick,std::function<const bool(const std::string &,int &)> idfromssk)
	{
		GetIdentityIDFromNick=idfromnick;
		GetIdentityIDFromSSK=idfromssk;
	}
	void SetValidateIdentityFunctions(std::function<const bool(const int)> validate, std::function<const bool(const int)> invalidate)
	{
		ValidateIdentity=validate;
		InvalidateIdentity=invalidate;
	}

private:
	std::string m_nick;
	bool m_connected;

	struct peerinfo
	{
		int m_identityid;
		std::string m_name;
		std::string m_publickey;
		std::string m_dateadded;
		std::string m_addedmethod;
		std::string m_lastseen;
		bool m_ignored;
		bool m_validated;
	};

	std::function<const bool(const std::string &,int &)> GetIdentityIDFromNick;
	std::function<const bool(const std::string &,int &)> GetIdentityIDFromSSK;
	std::function<const bool(const int)> ValidateIdentity;
	std::function<const bool(const int)> InvalidateIdentity;

	const bool HandleOptions(IRCClientConnection *client, const std::string &command);
	void SendOption(IRCClientConnection *client, const std::string &option,const std::string &optionvalue,const std::string &description,const std::string &validvalues);
	void SendPeer(IRCClientConnection *client, const peerinfo &peer);
	const bool HandlePeer(IRCClientConnection *client, const std::string &command);
	const bool HandleStatus(IRCClientConnection *client, const std::string &command);

};

#endif	// _ircflipservice_
