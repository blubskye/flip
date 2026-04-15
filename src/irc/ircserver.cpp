#include "ircserver.h"
#include "ircnick.h"
#include "irccommandresponse.h"
#include "ircchannel.h"
#include "../option.h"
#include "../stringfunctions.h"
#include "../rsakeypair.h"

#include <mbedtls/net_sockets.h>

#include <cstring>	// memset
#include <algorithm>

//debug
#include <iostream>

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <netinet/in.h>  // gcc - IPPROTO_ consts
	#include <netdb.h>       // gcc - addrinfo
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <unistd.h>
#endif

#ifdef _WIN32
bool IRCServer::m_wsastartup=false;
#endif

// CTCP: Returns true if the assembled IRC message body is a CTCP request that
// the server should silently drop instead of forwarding.
//
// Security rationale:
//   CTCP (Client-To-Client Protocol) requests are PRIVMSG/NOTICE messages whose
//   body is wrapped in ASCII 0x01 delimiters.  Common requests — VERSION, PING,
//   TIME, USERINFO, CLIENTINFO — cause the *recipient's* IRC client to reply
//   automatically with software version strings, system timestamps, and other
//   fingerprinting data.  Forwarding these through Freenet:
//     1. Leaks the recipient's IRC client version to any network observer.
//     2. Allows a single attacker to trigger floods of automatic replies from
//        every online user simultaneously (CTCP flood).
//     3. Stores version replies in Freenet KSKs, making them permanently
//        retrievable even after the victim goes offline.
//
//   CTCP ACTION (\x01ACTION text\x01) is the mechanism behind the /me command
//   and carries no auto-reply behaviour; it is therefore passed through.
//   All other CTCP types are dropped at the server boundary.
static bool IsCTCPRequest(const std::string &message)
{
	if(message.empty() || static_cast<unsigned char>(message[0]) != 0x01)
		return false;
	// Allow ACTION — used by IRC /me, carries no auto-reply
	if(message.size() >= 8 && message.substr(1, 7) == "ACTION ")
		return false;
	if(message.size() >= 8 && message.substr(1, 7) == "action ")
		return false;
	return true;
}

IRCServer::IRCServer():m_servername("flip"),m_flipservicenick("flipserv")
{
	// C10/C9: defaults — overridden in Start() once options are read.
	m_ircpassword="";
	m_maxclients=50;

#ifdef _WIN32
	if(m_wsastartup==false)
	{
		WSAData wsadata;
		WSAStartup(MAKEWORD(2,2),&wsadata);
		m_wsastartup=true;
	}
#endif
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_NEWCHANNELMESSAGE,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_NEWCHANNELNOTICE,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_NEWPRIVATEMESSAGE,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_NEWPRIVATENOTICE,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_IDENTITYINACTIVE,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_JOINCHANNEL,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_PARTCHANNEL,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_CONNECTED,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_DISCONNECTED,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_KEEPALIVE,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_SETTOPIC,this);
	FLIPEventSource::RegisterFLIPEventHandler(FLIPEvent::EVENT_FREENET_IDENTITYNAME,this);
	m_sslsetup=false;
	dbInitChannels();
}

struct second_deleter
{
	template<typename T>
	void operator()(const T& v) const
	{
		delete v.second;
	}
};

IRCServer::~IRCServer()
{
#ifdef _WIN32
	WSACleanup();
#endif
	ShutdownServerSSL();
	
	std::for_each(m_channels.begin(), m_channels.end(), second_deleter());
}

const bool IRCServer::GetPeerDBID(IRCClientConnection *client)
{
	if(client && client->PublicKey()!="")
	{
		SQLite3DB::Statement st=m_db->Prepare("SELECT IdentityID FROM tblIdentity WHERE PublicKey=?;");
		st.Bind(0,client->PublicKey());
		st.Step();
		if(st.RowReturned())
		{
			if(st.ResultNull(0)==false)
			{
				st.ResultInt(0,client->PeerDBID());
				return true;
			}
		}
	}
	return false;
}

void IRCServer::dbAddChannel(IRCChannel* chan) const
{
	SQLite3DB::Statement st=m_db->Prepare("INSERT INTO tblChannel(Name, Topic) VALUES(?,?);");
	st.Bind(0, chan->GetName());
	st.Bind(1, chan->GetTopic());
	st.Step();
}

void IRCServer::dbUpdateChannel(IRCChannel* chan) const
{
	SQLite3DB::Statement st=m_db->Prepare("UPDATE tblChannel set Topic=? WHERE Name=?;");
	st.Bind(0, chan->GetTopic());
	st.Bind(1, chan->GetName());
	st.Step();
}

void IRCServer::dbInitChannels()
{
	SQLite3DB::Recordset rs=m_db->Query("SELECT Name,Topic FROM tblChannel;");
	if(! rs.Count())
	{
		return;
	}

	while(!rs.AtEnd())
	{
		std::string name(rs.GetField(0));
		std::string topic(rs.GetField(1));
		
		IRCChannel* chan = new IRCChannel();
		chan->SetName(name);
		chan->SetTopic(topic);
		m_channels[name]=chan;
		rs.Next();
	}
}

void IRCServer::FindAndResolveNickCollision(const int identityid, const std::string &newnick, const bool notifyclients)
{
	bool isclient=IdentityConnectedAsClient(identityid);

	std::string orignick(m_ids[identityid].GetNick());
	if(isclient==false)
	{
		m_ids[identityid].SetNick(newnick);
		m_ids[identityid].ClearNickCollided();
	}

	for(std::map<int,idinfo>::iterator i=m_ids.begin(); i!=m_ids.end(); ++i)
	{
		if((*i).first!=identityid)
		{
			std::string idorignick((*i).second.GetNick());
			// Nick collision
			if(idorignick==m_ids[identityid].GetNick())
			{
				int tries=0;
				while((*i).second.GetNick()==m_ids[identityid].GetNick() && (tries++)<10)
				{

					if(m_ids[identityid].m_validated==true && (*i).second.ProgressNickCollision())
					{
						continue;
					}
					else if(isclient==false && (*i).second.m_validated==true && m_ids[identityid].ProgressNickCollision())
					{
						continue;
					}
					else if((*i).second.ProgressNickCollision())
					{
						continue;
					}
					else if(isclient==false)
					{
						m_ids[identityid].ProgressNickCollision();
					}

				}
			}

			if(idorignick!=(*i).second.GetNick())
			{
				SendNickChangeMessageToClients((*i).first,idorignick);
			}

		}
	}

	if(orignick!=m_ids[identityid].GetNick() && notifyclients==true)
	{
		SendNickChangeMessageToClients(identityid,orignick);
	}

}

void IRCServer::GetPublicKey(IRCClientConnection *client)
{
	if(client->PublicKey()=="")
	{
		SQLite3DB::Statement st=m_db->Prepare("SELECT PublicKey FROM tblLocalIdentity WHERE LocalIdentityID=?;");
		st.Bind(0,client->LocalDBID());
		st.Step();
		if(st.RowReturned())
		{
			st.ResultText(0,client->PublicKey());
		}
		if(client->PublicKey()!="" && m_ids.find(client->PeerDBID())!=m_ids.end())
		{
			m_ids[client->PeerDBID()].m_publickey=client->PublicKey();
			m_ids[client->PeerDBID()].m_basenick=client->Nick();
			m_ids[client->PeerDBID()].m_identityid=client->PeerDBID();
		}
	}
}

const bool IRCServer::HandleCommand(const IRCCommand &command, IRCClientConnection *client)
{
	std::cout << "received " << command.GetCommandString() << std::endl;

	GetPublicKey(client);

	// C10: handle PASS command — must arrive before NICK/USER.
	if(command.GetCommand()=="PASS")
	{
		if(command.GetParameters().size()>0)
		{
			std::string supplied(command.GetParameters()[0]);
			if(!supplied.empty() && supplied[0]==':')
			{
				supplied.erase(0,1);
			}
			if(m_ircpassword.empty() || supplied==m_ircpassword)
			{
				// Mark PASS as accepted on this connection.
				client->Registered()=(client->Registered() | IRCClientConnection::REG_PASS);
			}
			else
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_PASSDDMISMATCH,client->Nick(),":Password incorrect"));
				client->Disconnect();
			}
		}
		return true;
	}

	// C10: if a password is configured and not yet accepted, reject NICK/USER.
	if(!m_ircpassword.empty()
	   && (command.GetCommand()=="NICK" || command.GetCommand()=="USER")
	   && (client->Registered() & IRCClientConnection::REG_PASS)==0)
	{
		client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_PASSDDMISMATCH,client->Nick(),":Server password required — send PASS <password> first"));
		client->Disconnect();
		return true;
	}

	if(command.GetCommand()=="NICK")
	{
		if(command.GetParameters().size()>0)
		{
			std::string nick(command.GetParameters()[0]);
			if(nick.size()>0 && nick[0]==':')
			{
				nick.erase(0,1);
			}

			if(IRCNick::IsValid(nick))
			{
				if(NickInUse(client,nick,true)==false)
				{
					// set the nickname once before registering the connection
					if((client->Registered() & IRCClientConnection::REG_NICK)!=IRCClientConnection::REG_NICK)
					{
						SQLite3DB::Statement st=m_db->Prepare("SELECT LocalIdentityID, tblLocalIdentity.PublicKey, RSAPrivateKey, tblIdentity.IdentityID FROM tblLocalIdentity LEFT JOIN tblIdentity ON tblLocalIdentity.PublicKey=tblIdentity.PublicKey WHERE tblLocalIdentity.Name=?;");
						st.Bind(0,nick);
						st.Step();
						if(st.RowReturned()==false)
						{
							RSAKeyPair rsa;
							rsa.Generate();
							DateTime now;
							// H10: wrap both INSERTs in a transaction so tblLocalIdentity
							// and tblIdentity rows are always created atomically.  Without
							// this, a crash between the two INSERTs leaves an orphan row.
							m_db->Execute("BEGIN;");
							st=m_db->Prepare("INSERT INTO tblLocalIdentity(Name,DateAdded,RSAPublicKey,RSAPrivateKey) VALUES(?,?,?,?);");
							st.Bind(0,nick);
							st.Bind(1,now.Format("%Y-%m-%d %H:%M:%S"));
							st.Bind(2,rsa.GetEncodedPublicKey());
							st.Bind(3,rsa.GetEncodedPrivateKey());
							st.Step(true);
							client->LocalDBID()=st.GetLastInsertRowID();
							client->RSAPrivateKey()=rsa.GetEncodedPrivateKey();

							st=m_db->Prepare("INSERT INTO tblIdentity(Name,RSAPublicKey,DateAdded,AddedMethod) VALUES(?,?,?,?);");
							st.Bind(0,nick);
							st.Bind(1,rsa.GetEncodedPublicKey());
							st.Bind(2,now.Format("%Y-%m-%d %H:%M:%S"));
							st.Bind(3,"Local identity");
							st.Step(true);
							m_db->Execute("COMMIT;");
							client->PeerDBID()=st.GetLastInsertRowID();
						}
						else
						{
							st.ResultInt(0,client->LocalDBID());
							st.ResultText(1,client->PublicKey());
							st.ResultText(2,client->RSAPrivateKey());
							if(st.ResultNull(3)==false)
							{
								st.ResultInt(3,client->PeerDBID());
							}
						}

						if(client->PeerDBID()>0)
						{
							m_ids[client->PeerDBID()].m_lastircactivity.SetNowUTC();
							m_ids[client->PeerDBID()].m_basenick=nick;
							m_ids[client->PeerDBID()].m_publickey=client->PublicKey();
							m_ids[client->PeerDBID()].m_identityid=client->PeerDBID();
							m_ids[client->PeerDBID()].m_validated=true;
						}

						client->Registered()=(client->Registered() | IRCClientConnection::REG_NICK);
						client->Nick()=nick;

						FindAndResolveNickCollision(client->PeerDBID(),nick,false);

					}
					// change nick
					if((client->Registered() & (IRCClientConnection::REG_NICK | IRCClientConnection::REG_USER))==(IRCClientConnection::REG_NICK | IRCClientConnection::REG_USER))
					{
						std::string oldnick(client->Nick());

						if(oldnick!=nick)
						{
							SQLite3DB::Statement st=m_db->Prepare("UPDATE tblLocalIdentity SET Name=? WHERE LocalIdentityID=?;");
							st.Bind(0,nick);
							st.Bind(1,client->LocalDBID());
							st.Step();

							st=m_db->Prepare("UPDATE tblIdentity SET Name=? WHERE IdentityID=?;");
							st.Bind(0,nick);
							st.Bind(1,client->PeerDBID());
							st.Step();

							client->Nick()=nick;
							m_ids[client->PeerDBID()].m_basenick=nick;

							SendNickChangeMessageToClients(client->PeerDBID(),oldnick);

							// send irc event of changed nick
							std::map<std::string,std::string> params;
							params["nick"]=client->Nick();
							StringFunctions::Convert(client->LocalDBID(),params["localidentityid"]);
							DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_NICKCHANGE,params));
						}
					}

				}
				else
				{
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NICKNAMEINUSE,"*",":Nickname is already in use."));
				}
			}
			else
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_ERRONEUSNICKNAME,"*",":Erroneous nickname"));
			}
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NONICKNAMEGIVEN,"*",":No nickname given"));
		}
	}
	else if(command.GetCommand()=="USER")
	{
		if((client->Registered() & IRCClientConnection::REG_NICK)==IRCClientConnection::REG_NICK)
		{
			if((client->Registered() & IRCClientConnection::REG_USER)!=IRCClientConnection::REG_USER)
			{
				std::string clientcountstr("0");
				std::string channelcountstr("0");

				StringFunctions::Convert(m_clients.size(),clientcountstr);
				StringFunctions::Convert(m_idchannels.size(),channelcountstr);

				// TODO - check that parameters are valid!
				if(command.GetParameters().size()>0)
				{
					client->User()=command.GetParameters()[0];
				}
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WELCOME,client->Nick(),":Welcome to the Freenet IRC network "+client->Nick()));
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_YOURHOST,client->Nick(),":Your host is "+m_servername+" running version "+FLIP_VERSION));
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_CREATED,client->Nick(),":This server was created "+m_datestarted.Format("%Y-%m-%d")));
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_MYINFO,client->Nick(),m_servername+" "+FLIP_VERSION+" s v"));
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_LUSERCHANNELS,client->Nick(),channelcountstr+" :channels formed"));
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_LUSERME,client->Nick(),":I have "+clientcountstr+" clients and 1 server"));
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_USERHOST,client->Nick(),":"+client->Nick()+"=-n="+client->User()+"@freenet"));
				// reload MOTD and send to client
				ReloadMOTD();
				if(m_motdlines.size()>0)
				{
					SendMOTDLines(client);
				}

				std::map<std::string,std::string> params;
				params["nick"]=client->Nick();
				StringFunctions::Convert(client->LocalDBID(),params["localidentityid"]);

				client->LastActivity().SetNowUTC();
				DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_USERREGISTER,params));

				client->Registered()=(client->Registered() | IRCClientConnection::REG_USER);
			}
			else
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_ALREADYREGISTRED,client->Nick(),":You may not reregister"));
			}
		}
	}
	else if(command.GetCommand()=="TOPIC")
	{
		if(command.GetParameters().size()>0)
		{
			std::string name = command.GetParameters()[0];
			IRCChannel* chan = GetChannel(name);
			
			if(chan==NULL)
			{
				// Name is not valid
				return true;
			}

			if(command.GetParameters().size()>1)
			{
				// change topic
				
				if(client->JoinedChannels().find(name)==client->JoinedChannels().end())
				{
					//~ client is not in channel
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NOTONCHANNEL,client->Nick(),chan->GetName()+" :You're not on that channel"));
					return true;
				}
				
				std::string command_str = command.GetCommandString();
				size_t pos = command_str.find(":");
				
				if(pos==std::string::npos)
				{
					return true;
				}
				
				std::string topic = command_str.substr(pos+1);
				
				if(chan->GetTopic()==topic)
				{
					return true;
				}
				
				if(chan->SetTopic(topic)) //~ is the topic valid?
				{
					dbUpdateChannel(chan);
					std::map<std::string,std::string> params;
					params["nick"]=client->Nick();
					StringFunctions::Convert(client->LocalDBID(),params["localidentityid"]);
					params["channel"]=chan->GetName();
					params["topic"]=chan->GetTopic();
					
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_TOPIC,client->Nick(),chan->GetName()+" :"+chan->GetTopic()));
					DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_SETTOPIC,params));
				}
				else
				{
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_NOTOPIC,client->Nick(),chan->GetName()+" :No topic is set"));
				}
			}
			else
			{
				// view topic
				if(chan->GetTopicSet())
				{
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_TOPIC,client->Nick(),chan->GetName()+" :"+chan->GetTopic()));
				}
				else
				{
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_NOTOPIC,client->Nick(),chan->GetName()+" :No topic is set"));
				}
			}
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NEEDMOREPARAMS,client->Nick(),"TOPIC :Not enough parameters"));
		}
	}
	else if(command.GetCommand()=="JOIN")
	{
		if(command.GetParameters().size()>0)
		{
			std::vector<std::string> channels;
			StringFunctions::Split(command.GetParameters()[0],",",channels);

			for(std::vector<std::string>::iterator i=channels.begin(); i!=channels.end(); i++)
			{
				if((*i).size()>0 && (*i)[0]=='#')
				{
					std::string joinednicks(client->Nick());
					IRCChannel* pChan;
					if( (pChan = GetChannel(*i))==NULL )
					{
						//~ Channel name is not valid
						continue;
					}
					IRCChannel& chan = *pChan;

					for(std::set<int>::iterator j=m_idchannels[chan.GetName()].begin(); j!=m_idchannels[chan.GetName()].end(); j++)
					{
						if(m_ids[(*j)].GetNick()!="" && m_ids[(*j)].m_publickey!=client->PublicKey())
						{
							std::string idstr("");
							StringFunctions::Convert((*j),idstr);
							joinednicks+=" "+m_ids[(*j)].GetNick();
						}
					}

					client->SendCommand(IRCCommand(":"+client->Nick()+"!n="+client->User()+"@freenet JOIN :"+chan.GetName()));
					
					if(chan.GetTopicSet())
					{
						client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_TOPIC,client->Nick(),chan.GetName()+" :"+chan.GetTopic()));
					}
					else
					{
						client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_NOTOPIC,client->Nick(),chan.GetName()+" :No topic is set"));
					}
					
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_NAMREPLY,client->Nick()," = "+chan.GetName()+" :"+joinednicks));
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_ENDOFNAMES,client->Nick()," "+chan.GetName()+" :End of names"));

					client->JoinedChannels().insert(chan.GetName());
					if(client->PeerDBID()>0)
					{
						SendJoinMessageToClients(client->PeerDBID(),chan.GetName());
						m_idchannels[chan.GetName()].insert(client->PeerDBID());
					}

					std::map<std::string,std::string> params;
					params["nick"]=client->Nick();
					StringFunctions::Convert(client->LocalDBID(),params["localidentityid"]);
					params["channel"]=chan.GetName();

					client->LastActivity().SetNowUTC();
					DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_JOINCHANNEL,params));
				}
			}

		}
	}
	else if(command.GetCommand()=="PART")
	{
		if(command.GetParameters().size()>0)
		{
			std::vector<std::string> channels;
			StringFunctions::Split(command.GetParameters()[0],",",channels);

			for(std::vector<std::string>::iterator i=channels.begin(); i!=channels.end(); i++)
			{
				if((*i).size()>0 && (*i)[0]=='#' && IRCChannel::ValidName((*i)))
				{
					if(client->JoinedChannels().find((*i))!=client->JoinedChannels().end())
					{
						client->SendCommand(IRCCommand(":"+client->Nick()+"!n="+client->User()+"@freenet PART :"+(*i)));

						client->JoinedChannels().erase((*i));
						if(client->PeerDBID()>0)
						{
							SendPartMessageToClients(client->PeerDBID(),(*i));
							m_idchannels[(*i)].erase(client->PeerDBID());
						}

						std::map<std::string,std::string> params;
						params["nick"]=client->Nick();
						StringFunctions::Convert(client->LocalDBID(),params["localidentityid"]);
						params["channel"]=(*i);

						client->LastActivity().SetNowUTC();
						DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_PARTCHANNEL,params));
					}
				}
			}
		}
	}
	else if(command.GetCommand()=="PRIVMSG" || command.GetCommand()=="NOTICE")
	{
		std::string cmd=command.GetCommand();
		if(command.GetParameters().size()>1)
		{
			// M4: assemble and cap message body before routing.
			// IRC spec says a line must fit in 512 bytes including the prefix and
			// command; we cap the message content portion at 512 chars to prevent
			// oversized messages from consuming memory or being mis-handled.
			std::string cappmessage;
			{
				std::vector<std::string>::const_iterator mi=(command.GetParameters().begin()+1);
				if(mi!=command.GetParameters().end())
				{
					cappmessage=(*mi);
					++mi;
				}
				for(;mi!=command.GetParameters().end();++mi)
				{
					cappmessage+=" "+(*mi);
				}
			}
			if(cappmessage.size()>512)
			{
				cappmessage=cappmessage.substr(0,512);
			}

			// message to channel
			if(command.GetParameters()[0].size()>0 && command.GetParameters()[0][0]=='#' && IRCChannel::ValidName(command.GetParameters()[0]))
			{
				IRCChannel chan;
				std::string message(cappmessage);

				chan.SetName(command.GetParameters()[0]);

				std::map<std::string,std::string> params;

				// CTCP: Drop any non-ACTION CTCP request before it reaches Freenet.
				// Recipients' IRC clients auto-reply to CTCP — forwarding them leaks
				// version info and enables amplification floods.
				if(IsCTCPRequest(message))
				{
					return true;
				}

				params["nick"]=client->Nick();
				StringFunctions::Convert(client->LocalDBID(),params["localidentityid"]);
				params["message"]=message;
				params["channel"]=chan.GetName();

				client->LastActivity().SetNowUTC();

				if(cmd=="NOTICE")
				{
					DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_CHANNELNOTICE,params));
				}
				else
				{
					DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_CHANNELMESSAGE,params));
				}
			}
			// message to another user
			else
			{
				bool sentlocal=false;
				int recipientid=0;
				std::string message(cappmessage);

				// message sent to local flip service to control flip
				if(command.GetParameters()[0]==m_flipservicenick)
				{
					// CTCP: Never forward CTCP to the service bot — it cannot
					// respond to them and the request would be silently discarded
					// anyway, but we drop it here explicitly to avoid any future
					// service handler accidentally responding.
					if(IsCTCPRequest(message))
					{
						return true;
					}
					//HandleFLIPServiceMessage(client,command);
					m_flipservice.HandleCommand(command,client);
				}
				else
				{
					std::map<std::string,std::string> params;
					params["nick"]=client->Nick();
					StringFunctions::Convert(client->LocalDBID(),params["localidentityid"]);
					params["message"]=message;

					GetIdentityIDFromNick(command.GetParameters()[0],recipientid);
					StringFunctions::Convert(recipientid,params["recipientidentityid"]);

					// CTCP: Drop non-ACTION CTCP requests for direct peer-to-peer
					// messages too.  Local delivery (line below) would pass the
					// raw bytes straight to the recipient's IRC client which would
					// auto-reply, and Freenet delivery would store the request in
					// a KSK where it remains retrievable indefinitely.
					if(IsCTCPRequest(message))
					{
						return true;
					}

					// H1-compat: signal the freenet inserter to use PKCS#1 v1.5 (legacy)
					// if the user ran /1024 <nick> for this recipient.
					if(m_ids.count(recipientid) && m_ids[recipientid].m_legacycompat)
					{
						params["legacycompat"]="true";
					}

					client->LastActivity().SetNowUTC();

					// see if client is connected locally to this server and send directly, otherwise insert message in Freenet
					for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); i++)
					{
						if((*i)->PeerDBID()==recipientid)
						{
							if(client->PeerDBID()>0 || GetPeerDBID(client)==true)
							{
								std::string peerdbid("");
								StringFunctions::Convert(client->PeerDBID(),peerdbid);
								(*i)->SendCommand(IRCCommand(":"+m_ids[client->PeerDBID()].GetNick()+" "+cmd+" "+(*i)->Nick()+" :"+message));
								sentlocal=true;
							}
						}
					}
					if(sentlocal==false)
					{
						if(m_ids.find(recipientid)!=m_ids.end())
						{
							if(cmd=="NOTICE")
							{
								DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_PRIVATENOTICE,params));
							}
							else
							{
								DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_PRIVATEMESSAGE,params));
							}
						}
						else
						{
							client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NOSUCHNICK,client->Nick(),command.GetParameters()[0]+" :No such nick"));
						}
					}
				}
			}
		}
	}
	else if(command.GetCommand()=="LIST")
	{
		// list all channels
		if(command.GetParameters().size()==0 || (command.GetParameters().size()>0 && command.GetParameters()[0].size()==0) )
		{
			for(std::map<std::string,std::set<int> >::iterator i=m_idchannels.begin(); i!=m_idchannels.end(); i++)
			{
				IRCChannel* chan = GetChannel((*i).first);
				if(chan==NULL) {continue;}
				std::string countstr("0");
				StringFunctions::Convert((*i).second.size(),countstr);
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_LIST,client->Nick(),(*i).first+" "+countstr+" :"+chan->GetTopic()));
			}
		}
		// list only specific channels
		else
		{
			std::vector<std::string> channels;
			StringFunctions::Split(command.GetParameters()[0],",",channels);
			for(std::vector<std::string>::iterator i=channels.begin(); i!=channels.end(); i++)
			{
				IRCChannel* chan = GetChannel(*i);
				if(chan!=NULL)
				{
					std::string countstr("0");
					if(m_idchannels.find(chan->GetName())!=m_idchannels.end())
					{
						StringFunctions::Convert((*m_idchannels.find(chan->GetName())).second.size(),countstr);
					}
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_LIST,client->Nick(),chan->GetName()+" "+countstr+" :"+chan->GetTopic()));
				}
			}
		}
		client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_LISTEND,client->Nick(),":End of list"));
	}
	else if(command.GetCommand()=="NAMES")
	{
		std::vector<std::string> channels;
		int channelcount=0;
		IRCChannel chan;

		if(command.GetParameters().size()==0)
		{
			for(std::map<std::string,std::set<int> >::const_iterator i=m_idchannels.begin(); i!=m_idchannels.end(); i++)
			{
				channels.push_back((*i).first);
			}
		}
		else if(command.GetParameters().size()==1)
		{
			StringFunctions::Split(command.GetParameters()[0],",",channels);
		}

		for(std::vector<std::string>::const_iterator i=channels.begin(); i!=channels.end(); i++)
		{
			if(m_idchannels.find((*i))!=m_idchannels.end())
			{
				channelcount++;
				chan.SetName((*i));
				std::string joinednicks("");
				int nickcount=0;
				for(std::set<int>::const_iterator j=m_idchannels[(*i)].begin(); j!=m_idchannels[(*i)].end(); j++)
				{
					if(m_ids[(*j)].GetNick()!="" && m_ids[(*j)].m_publickey!=client->PublicKey())
					{
						std::string idstr("");
						StringFunctions::Convert((*j),idstr);
						if(joinednicks!="")
						{
							joinednicks+=" ";
						}
						joinednicks+=m_ids[(*j)].GetNick();
						nickcount++;
					}
					else if(m_ids[(*j)].m_publickey==client->PublicKey())
					{
						if(joinednicks!="")
						{
							joinednicks+=" ";
						}
						joinednicks+=client->Nick();
						nickcount++;
					}
					if(nickcount==10)
					{
						client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_NAMREPLY,client->Nick()," = "+chan.GetName()+" :"+joinednicks));
						nickcount=0;
						joinednicks="";
					}
				}
				if(nickcount>0)
				{
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_NAMREPLY,client->Nick()," = "+chan.GetName()+" :"+joinednicks));
				}
			}
		}

		if(channelcount==0 || channelcount>1)
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_ENDOFNAMES,client->Nick(),":End of names"));
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_ENDOFNAMES,client->Nick()," "+chan.GetName()+" :End of names"));
		}

	}
	else if(command.GetCommand()=="WHO")
	{
		/* allow 2nd parameter - must be o (operator) */
		if((command.GetParameters().size()==1 || command.GetParameters().size()==2))
		{
			const std::string param0(command.GetParameters()[0]);
			if(command.GetParameters().size()==2 && command.GetParameters()[1]!="o")
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_UNKNOWNCOMMAND,client->Nick(),":"+command.GetCommand()+" Unknown command"));
			}
			else
			{
				// don't handle wildcards for now - must match exactly
				// first check for channels that match
				if(m_channels.find(param0)!=m_channels.end())
				{
					for(std::set<int>::const_iterator i=m_idchannels[param0].begin(); i!=m_idchannels[param0].end(); ++i)
					{
						/*
						352    RPL_WHOREPLY
						"<channel> <user> <host> <server> <nick>
						( "H" / "G" > ["*"] [ ( "@" / "+" ) ]
						:<hopcount> <real name>"
						*/
						
						client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOREPLY,client->Nick(),param0+" ~"+m_ids[(*i)].GetIRCUser()+" freenet "+m_servername+" "+m_ids[(*i)].GetNick()+" H :0 Anonymous"));
					}
				}
				// next check users that match
				else
				{
					for(std::map<int,idinfo>::const_iterator i=m_ids.begin(); i!=m_ids.end(); i++)
					{
						if((*i).second.GetNick()==param0)
						{
							client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOREPLY,client->Nick(),"* ~"+(*i).second.GetIRCUser()+" freenet "+m_servername+" +"+(*i).second.GetNick()+" H :0 Anonymous"));
						}
					}
				}

				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_ENDOFWHO,client->Nick(),param0+" :End of WHO list"));
			}
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NEEDMOREPARAMS,client->Nick(),"WHO :Not enough parameters"));
		}

	}
	else if(command.GetCommand()=="WHOIS")
	{
		/* allow (but ignore) a second parameter, some clients do WHOIS <nick> <nick> */
		if((command.GetParameters().size()==1) || (command.GetParameters().size()==2))
		{
			int identityid=0;
			std::string idlestr("");

			GetIdentityIDFromNick(command.GetParameters()[0],identityid);

			if(m_ids.find(identityid)!=m_ids.end() && identityid!=client->PeerDBID())
			{
				int chancount=0;
				std::string chanstring("");

				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOISUSER,client->Nick(),command.GetParameters()[0]+" ~"+m_ids[identityid].GetIRCUser()+" freenet * :Anonymous"));

				// send joined channels
				for(std::map<std::string,std::set<int> >::const_iterator i=m_idchannels.begin(); i!=m_idchannels.end(); i++)
				{
					if((*i).second.find(identityid)!=(*i).second.end())
					{
						chancount+=1;
						if(chanstring!="")
						{
							chanstring+=" ";
						}
						chanstring+=(*i).first;
					}
					if(chancount==10)
					{
						client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOISCHANNELS,client->Nick(),command.GetParameters()[0]+" :"+chanstring));
						chancount=0;
						chanstring="";
					}
				}
				if(chancount>0)
				{
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOISCHANNELS,client->Nick(),command.GetParameters()[0]+" :"+chanstring));
				}

				// send idle time
				DateTime now;
				now.SetNowUTC();
				StringFunctions::Convert(DateTime::DifferenceS(now,m_ids[identityid].m_lastircactivity),idlestr);
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOISIDLE,client->Nick(),command.GetParameters()[0]+" "+idlestr+" :seconds idle"));

				// end whois
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_ENDOFWHOIS,client->Nick(),":End of /WHOIS list."));
			}
			// client's own identity
			else if(command.GetParameters()[0]==client->Nick())
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOISUSER,client->Nick(),client->Nick()+" ~"+m_ids[identityid].GetIRCUser()+" freenet * :Anonymous"));

				int chancount=0;
				std::string chanstring("");
				for(std::set<std::string>::const_iterator i=client->JoinedChannels().begin(); i!=client->JoinedChannels().end(); i++)
				{
					chancount+=1;
					if(chanstring!="")
					{
						chanstring+=" ";
					}
					chanstring+=(*i);
					if(chancount==10)
					{
						client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOISCHANNELS,client->Nick(),client->Nick()+" :"+chanstring));
						chancount=0;
						chanstring="";
					}
				}
				if(chancount>0)
				{
					client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOISCHANNELS,client->Nick(),client->Nick()+" :"+chanstring));
				}

				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_WHOISIDLE,client->Nick(),client->Nick()+" 0 :seconds idle"));

				// end whois
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_ENDOFWHOIS,client->Nick(),":End of /WHOIS list."));
			}
			else
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NOSUCHNICK,client->Nick(),command.GetParameters()[0]+" :No such nick"));
			}
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NEEDMOREPARAMS,client->Nick(),"WHOIS :Not enough parameters"));
		}
	}
	else if(command.GetCommand()=="MOTD")
	{
		if(m_motdlines.size()>0)
		{
			SendMOTDLines(client);
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NOMOTD,client->Nick(),":No Message of the Day"));
		}
	}
	else if(command.GetCommand()=="PING")
	{
		if(command.GetParameters().size()>=1 && command.GetParameters()[0]==client->Nick())
		{
			client->SendCommand(":"+m_servername+" PONG "+m_servername+" :"+client->Nick());
		}
		else if(command.GetParameters().size()==1 && command.GetParameters()[0]==m_servername)
		{
			client->SendCommand(":"+m_servername+" PONG "+m_servername);
		}
		else if(command.GetParameters().size()>=1 && command.GetParameters()[0].size()>0)
		{
			client->SendCommand(":"+m_servername+" PONG "+m_servername+" "+command.GetParameters()[0]);
		}
	}
	else if(command.GetCommand()=="QUIT")
	{
		//Just disconnect client here - Update method will take care of cleaning up the connection
		client->Disconnect();
	}
	// C1/H1-compat: "/1024 <nick>" enables PKCS#1 v1.5 (legacy) encryption when
	// sending private messages to that peer.  Intended for peers still running
	// old FLIP builds that do not understand OAEP (H1).  The server also warns
	// the local user whenever it receives a message encrypted with < 2048-bit key.
	else if(command.GetCommand()=="1024")
	{
		if(command.GetParameters().size()>0)
		{
			std::string targetnick(command.GetParameters()[0]);
			if(!targetnick.empty() && targetnick[0]==':')
			{
				targetnick.erase(0,1);
			}
			int identityid=0;
			if(GetIdentityIDFromNick(targetnick,identityid))
			{
				m_ids[identityid].m_legacycompat=true;
				client->SendCommand(IRCCommand(":"+m_servername+" NOTICE "+client->Nick()+" :Legacy compat (PKCS#1 v1.5) enabled for "+targetnick+".  Messages to this peer use old-format encryption.  Disable with /4096 "+targetnick));
			}
			else
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NOSUCHNICK,client->Nick(),targetnick+" :No such nick"));
			}
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NEEDMOREPARAMS,client->Nick(),"1024 :Usage: /1024 <nick>  — enable legacy compat for <nick>"));
		}
	}
	// C1/H1-compat: "/4096 <nick>" disables legacy compat for that peer, restoring
	// OAEP/SHA-256 (the secure default for H1-patched FLIP builds).
	else if(command.GetCommand()=="4096")
	{
		if(command.GetParameters().size()>0)
		{
			std::string targetnick(command.GetParameters()[0]);
			if(!targetnick.empty() && targetnick[0]==':')
			{
				targetnick.erase(0,1);
			}
			int identityid=0;
			if(GetIdentityIDFromNick(targetnick,identityid))
			{
				m_ids[identityid].m_legacycompat=false;
				client->SendCommand(IRCCommand(":"+m_servername+" NOTICE "+client->Nick()+" :OAEP (modern) encryption restored for "+targetnick+"."));
			}
			else
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NOSUCHNICK,client->Nick(),targetnick+" :No such nick"));
			}
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NEEDMOREPARAMS,client->Nick(),"4096 :Usage: /4096 <nick>  — restore OAEP for <nick>"));
		}
	}
	// H1-compat: "/legacy #channel" marks the channel and all current members as
	// legacy compat (PKCS#1 v1.5).  Identities that join the channel later are
	// automatically flagged.  Channel messages themselves are always plaintext SSK
	// posts; this setting only affects encrypted private messages to channel members.
	else if(command.GetCommand()=="LEGACY")
	{
		if(command.GetParameters().size()>0)
		{
			std::string channame(command.GetParameters()[0]);
			if(!channame.empty() && channame[0]==':')
			{
				channame.erase(0,1);
			}
			if(channame.size()>0 && channame[0]=='#' && IRCChannel::ValidName(channame))
			{
				m_legacychannels.insert(channame);
				// mark all current channel members as legacy compat
				if(m_idchannels.count(channame))
				{
					for(std::set<int>::const_iterator i=m_idchannels[channame].begin(); i!=m_idchannels[channame].end(); ++i)
					{
						if(m_ids.count(*i))
						{
							m_ids[*i].m_legacycompat=true;
						}
					}
				}
				client->SendCommand(IRCCommand(":"+m_servername+" NOTICE "+client->Nick()+" :Legacy compat (PKCS#1 v1.5) enabled for channel "+channame+".  All members use old-format encryption.  Disable with /modern "+channame));
			}
			else
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NOSUCHCHANNEL,client->Nick(),channame+" :Invalid or unknown channel name"));
			}
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NEEDMOREPARAMS,client->Nick(),"LEGACY :Usage: /legacy #channel  — enable legacy compat for all members of a channel"));
		}
	}
	// H1-compat: "/modern #channel" removes channel legacy compat, restoring
	// OAEP/SHA-256 for members not in any other legacy channel.
	else if(command.GetCommand()=="MODERN")
	{
		if(command.GetParameters().size()>0)
		{
			std::string channame(command.GetParameters()[0]);
			if(!channame.empty() && channame[0]==':')
			{
				channame.erase(0,1);
			}
			if(channame.size()>0 && channame[0]=='#' && IRCChannel::ValidName(channame))
			{
				m_legacychannels.erase(channame);
				// clear legacy compat for members no longer in any legacy channel
				if(m_idchannels.count(channame))
				{
					for(std::set<int>::const_iterator i=m_idchannels[channame].begin(); i!=m_idchannels[channame].end(); ++i)
					{
						int identityid=*i;
						if(!m_ids.count(identityid))
						{
							continue;
						}
						// preserve flag if identity is still in another legacy channel
						bool inother=false;
						for(std::set<std::string>::const_iterator lc=m_legacychannels.begin(); lc!=m_legacychannels.end(); ++lc)
						{
							if(m_idchannels.count(*lc) && m_idchannels[*lc].count(identityid))
							{
								inother=true;
								break;
							}
						}
						if(!inother)
						{
							m_ids[identityid].m_legacycompat=false;
						}
					}
				}
				client->SendCommand(IRCCommand(":"+m_servername+" NOTICE "+client->Nick()+" :Modern (OAEP) encryption restored for channel "+channame+"."));
			}
			else
			{
				client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NOSUCHCHANNEL,client->Nick(),channame+" :Invalid or unknown channel name"));
			}
		}
		else
		{
			client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_NEEDMOREPARAMS,client->Nick(),"MODERN :Usage: /modern #channel  — restore OAEP encryption for all members of a channel"));
		}
	}
	else
	{
		client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::ERR_UNKNOWNCOMMAND,client->Nick(),":"+command.GetCommand()+" Unknown command"));
	}

	return true;
}

const bool IRCServer::HandleFLIPEvent(const FLIPEvent &flipevent)
{
	std::map<std::string,std::string> params=flipevent.GetParameters();
	int identityid=0;
	DateTime sentdate;
	DateTime insertday;
	DateTime thirtyminutesago;
	DateTime fiveminutesfromnow;
	DateTime now;

	if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_CONNECTED)
	{
		for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); i++)
		{
			(*i)->SendCommand(IRCCommand("NOTICE * :Freenet connection established"));
		}
		m_flipservice.SetConnected(true);
		return true;
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_DISCONNECTED)
	{
		for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); i++)
		{
			(*i)->SendCommand(IRCCommand("NOTICE * :Freenet connection dropped"));
		}
		m_flipservice.SetConnected(false);
		return true;
	}
	else
	{
		thirtyminutesago.Add(0,-30);
		fiveminutesfromnow.Add(0,5);

		StringFunctions::Convert(params["identityid"],identityid);

		// First make sure the sent date is valid and if we haven't already seen a message from this id
		// make sure that the message is from the past 30 minutes, otherwise discard the message
		if(DateTime::TryParse(params["sentdate"],sentdate))
		{
			if(m_idhassent.find(identityid)!=m_idhassent.end() || (sentdate>=thirtyminutesago && sentdate<=fiveminutesfromnow))
			{
				m_idhassent.insert(identityid);
			}
			else
			{
				// message older than 30 minutes get silently discarded
				return false;
			}
		}
		else
		{
			m_log->Debug("IRCServer::HandleFLIPEvent error parsing date '"+params["sentdate"]+"'");
			return false;
		}

		DateTime::TryParse(params["insertday"],insertday);
		insertday.Set(insertday.Year(),insertday.Month(),insertday.Day(),0,0,0);

		LoadIdentity(identityid);

		// The sent date is OK, and we do want to handle this message
		// Now make sure that the edition of the message is one after the last edition
		// we already received.  Otherwise we will queue the message up to x seconds to
		// wait for the missing edition(s)

		int thisedition=0;
		int lastedition=-1;
		StringFunctions::Convert(params["edition"],thisedition);
		if(m_ids[identityid].m_lastdayedition.find(insertday)!=m_ids[identityid].m_lastdayedition.end())
		{
			lastedition=m_ids[identityid].m_lastdayedition[insertday];
		}
		else
		{
			lastedition=thisedition-1;
		}

		if(thisedition<=lastedition+1)
		{
			ProcessFLIPEvent(identityid,flipevent);
		}
		else
		{
			m_ids[identityid].m_messagequeue.insert(idinfo::messagequeueitem(flipevent,thisedition,insertday,now));
		}

		// the identity is active, so send the active message
		std::map<std::string,std::string> activeparams;
		activeparams["identityid"]=params["identityid"];
		DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IDENTITYACTIVE,activeparams));

		return true;
	}

}

const bool IRCServer::IdentityConnectedAsClient(const int identityid) const
{
	return (std::find_if(m_clients.begin(),m_clients.end(),[identityid](IRCClientConnection *client){return client->PeerDBID()==identityid; })!=m_clients.end());
}

void IRCServer::LoadIdentity(const int identityid)
{
	// insert sender into ids list if they aren't already there
	if(m_ids.find(identityid)==m_ids.end())
	{
		SQLite3DB::Statement st=m_db->Prepare("SELECT Name, PublicKey, Validated FROM tblIdentity WHERE IdentityID=?;");
		st.Bind(0,identityid);
		st.Step();
		if(st.RowReturned())
		{
			int validated=0;
			st.ResultText(0,m_ids[identityid].m_basenick);
			st.ResultText(1,m_ids[identityid].m_publickey);
			st.ResultInt(2,validated);
			m_ids[identityid].m_identityid=identityid;
			validated==1 ? m_ids[identityid].m_validated=true : m_ids[identityid].m_validated=false;

			FindAndResolveNickCollision(identityid,m_ids[identityid].m_basenick,false);

		}
	}
}

const bool IRCServer::GetIdentityIDFromNick(const std::string &nick, int &identityid) const
{
	// match nick exactly
	for(std::map<int,idinfo>::const_iterator i=m_ids.begin(); i!=m_ids.end(); ++i)
	{
		if((*i).second.GetNick()==nick)
		{
			identityid=(*i).first;
			return true;
		}
	}

	return false;
}

const bool IRCServer::GetIdentityIDFromSSK(const std::string &ssk, int &identityid) const
{
	for(std::map<int,idinfo>::const_iterator i=m_ids.begin(); i!=m_ids.end(); ++i)
	{
		if((*i).second.m_publickey==ssk)
		{
			identityid=(*i).first;
			return true;
		}
	}

	SQLite3DB::Statement st=m_db->Prepare("SELECT IdentityID FROM tblIdentity WHERE PublicKey=?;");
	st.Bind(0,ssk);
	st.Step();
	if(st.RowReturned())
	{
		st.ResultInt(0,identityid);
		return true;
	}

	return false;
}

const bool IRCServer::NickInUse(IRCClientConnection *client, const std::string &nick, const bool clientsonly) const
{
	for(std::vector<IRCClientConnection *>::const_iterator i=m_clients.begin(); i!=m_clients.end(); ++i)
	{
		if((*i)!=client && (*i)->Nick()==nick)
		{
			return true;
		}
	}
	if(clientsonly==false)
	{
		int peerdbid=client->PeerDBID();
		if(peerdbid<1)
		{
			SQLite3DB::Statement st=m_db->Prepare("SELECT tblIdentity.IdentityID FROM tblLocalIdentity LEFT JOIN tblIdentity ON tblLocalIdentity.PublicKey=tblIdentity.PublicKey WHERE tblLocalIdentity.Name=?;");
			st.Bind(0,nick);
			st.Step();
			if(st.RowReturned())
			{
				st.ResultInt(0,peerdbid);
			}
		}

		for(std::map<int,idinfo>::const_iterator i=m_ids.begin(); i!=m_ids.end(); ++i)
		{
			if((*i).second.GetNick()==nick && (*i).second.m_identityid!=peerdbid)
			{
				return true;
			}
		}
	}
	return false;
}

void IRCServer::ReloadMOTD()
{
	std::string temp("");
	Option option;
	option.Get("IRCMOTD",temp);

	m_motdlines.clear();
	if(temp.size()>0)
	{
		// convert \r\n and \r to \n before splitting lines
		temp=StringFunctions::Replace(temp,"\r\n","\n");
		temp=StringFunctions::Replace(temp,"\r","\n");
		StringFunctions::Split(temp,"\n",m_motdlines);
	}
	else
	{
		m_motdlines.clear();
	}
}

void IRCServer::ProcessFLIPEvent(const int identityid, const FLIPEvent &flipevent)
{
	//DateTime sentdate;
	DateTime insertday;
	std::map<std::string,std::string> params=flipevent.GetParameters();
	int edition=0;

	DateTime::TryParse(params["insertday"],insertday);
	insertday.Set(insertday.Year(),insertday.Month(),insertday.Day(),0,0,0);
	//DateTime::TryParse(params["sentdate"],sentdate);
	StringFunctions::Convert(params["edition"],edition);
	if(m_ids[identityid].m_lastdayedition[insertday]<edition)
	{
		m_ids[identityid].m_lastdayedition[insertday]=edition;
	}

	if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_KEEPALIVE)
	{
		// join and part channels as required
		if(params.find("channels")!=params.end())
		{
			std::vector<std::string> channels;
			StringFunctions::Split(params["channels"]," ",channels);

			// part channels not in list
			for(std::map<std::string,std::set<int> >::iterator i=m_idchannels.begin(); i!=m_idchannels.end(); ++i)
			{
				if((*i).second.find(identityid)!=(*i).second.end() && std::find(channels.begin(),channels.end(),(*i).first)==channels.end())
				{
					SendPartMessageToClients(identityid,(*i).first);

					(*i).second.erase(identityid);

					m_ids[identityid].m_lastircactivity.SetNowUTC();
				}
			}

			// join channels not already joined
			for(std::vector<std::string>::const_iterator ci=channels.begin(); ci!=channels.end(); ++ci)
			{
				if((*ci).size()>1 && (*ci)[0]=='#' && IRCChannel::ValidName((*ci))==true)
				{
					if(m_idchannels[(*ci)].find(identityid)==m_idchannels[(*ci)].end())
					{
						m_idchannels[(*ci)].insert(identityid);

						// H1-compat: auto-enable legacy compat when joining a legacy channel
						if(m_legacychannels.count(*ci) && m_ids.count(identityid))
						{
							m_ids[identityid].m_legacycompat=true;
						}

						SendJoinMessageToClients(identityid,(*ci));

						m_ids[identityid].m_lastircactivity.SetNowUTC();
					}
				}
			}
		}
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_NEWCHANNELMESSAGE)
	{
		SendChannelMessageToClients(identityid,params["channel"],StringFunctions::TrimTrailingWhitespace(params["message"]),MessageType::MT_MESSAGE);
		m_ids[identityid].m_lastircactivity.SetNowUTC();
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_NEWCHANNELNOTICE)
	{
		SendChannelMessageToClients(identityid,params["channel"],StringFunctions::TrimTrailingWhitespace(params["message"]),MessageType::MT_NOTICE);
		m_ids[identityid].m_lastircactivity.SetNowUTC();
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_SETTOPIC)
	{
		SendTopicToClients(identityid,params["channel"],StringFunctions::TrimTrailingWhitespace(params["topic"]));
		m_ids[identityid].m_lastircactivity.SetNowUTC();
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_NEWPRIVATEMESSAGE)
	{
		SendPrivateMessageToClients(identityid,params["recipient"],params["encryptedmessage"],MessageType::MT_MESSAGE);
		m_ids[identityid].m_lastircactivity.SetNowUTC();
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_NEWPRIVATENOTICE)
	{
		SendPrivateMessageToClients(identityid,params["recipient"],params["encryptedmessage"],MessageType::MT_NOTICE);
		m_ids[identityid].m_lastircactivity.SetNowUTC();
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_IDENTITYINACTIVE)
	{
		// send part command to connected clients
		for(std::map<std::string,std::set<int> >::iterator i=m_idchannels.begin(); i!=m_idchannels.end(); ++i)
		{
			if((*i).second.find(identityid)!=(*i).second.end())
			{
				SendPartMessageToClients(identityid,(*i).first);

				(*i).second.erase(identityid);
			}
		}
		// remove the id from our cache, it is no longer active
		m_ids.erase(identityid);
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_PARTCHANNEL)
	{
		// send part command to all connected clients in channel
		for(std::map<std::string,std::set<int> >::iterator i=m_idchannels.begin(); i!=m_idchannels.end(); ++i)
		{
			if((*i).second.find(identityid)!=(*i).second.end())
			{
				if((*i).first==params["channel"])
				{
					SendPartMessageToClients(identityid,(*i).first);

					(*i).second.erase(identityid);
				}
			}
		}
		m_ids[identityid].m_lastircactivity.SetNowUTC();
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_JOINCHANNEL)
	{
		std::string idstr(params["identityid"]);

		// send join command to connected clients
		if(m_idchannels[params["channel"]].find(identityid)==m_idchannels[params["channel"]].end())
		{
			m_idchannels[params["channel"]].insert(identityid);

			// H1-compat: auto-enable legacy compat when joining a legacy channel
			if(m_legacychannels.count(params["channel"]) && m_ids.count(identityid))
			{
				m_ids[identityid].m_legacycompat=true;
			}

			SendJoinMessageToClients(identityid,params["channel"]);
		}
		m_ids[identityid].m_lastircactivity.SetNowUTC();
	}
	else if(flipevent.GetType()==FLIPEvent::EVENT_FREENET_IDENTITYNAME)
	{
		// nick has changed, and it's valid - send to connected clients
		if(IdentityConnectedAsClient(identityid)==false && m_ids[identityid].m_basenick!=params["name"] && IRCNick::IsValid(params["name"]))
		{
			std::string oldnick=m_ids[identityid].GetNick();

			SQLite3DB::Statement st=m_db->Prepare("UPDATE tblIdentity SET Name=? WHERE IdentityID=?;");
			st.Bind(0,params["name"]);
			st.Bind(1,identityid);
			st.Step();

			FindAndResolveNickCollision(identityid,params["name"],true);

			m_ids[identityid].m_lastircactivity.SetNowUTC();
		}
	}

}

void IRCServer::SendChannelMessageToClients(const int identityid, const std::string &channel, const std::string &message, const MessageType messagetype)
{
	//std::string idstr("");
	//StringFunctions::Convert(identityid,idstr);

	std::string messcmd("");

	switch(messagetype)
	{
	case MessageType::MT_NOTICE:
		messcmd="NOTICE";
		break;
	case MessageType::MT_MESSAGE:
	default:
		messcmd="PRIVMSG";
		break;
	}

	LoadIdentity(identityid);

	// make sure identity is joined to channels
	if(m_idchannels[channel].find(identityid)==m_idchannels[channel].end())
	{
		m_idchannels[channel].insert(identityid);

		SendJoinMessageToClients(identityid,channel);
	}

	// send message to connected clients
	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); ++i)
	{
		GetPublicKey((*i));

		// don't resend the message to the client that sent it in the first place
		if((*i)->PublicKey()!=m_ids[identityid].m_publickey && (*i)->JoinedChannels().find(channel)!=(*i)->JoinedChannels().end())
		{
			(*i)->SendCommand(IRCCommand(":"+m_ids[identityid].GetNick()+" "+messcmd+" "+channel+" :"+message));
		}
	}
}

void IRCServer::SendTopicToClients(const int identityid, const std::string &channel, const std::string &topic)
{
	LoadIdentity(identityid);
	
	// make sure identity is joined to channel
	if(m_idchannels[channel].find(identityid)==m_idchannels[channel].end())
	{
		m_idchannels[channel].insert(identityid);
		SendJoinMessageToClients(identityid,channel);
	}
	
	IRCChannel* chan = GetChannel(channel);
	if(chan==NULL) return;
	if(chan->GetTopic()==topic) return;
	
	chan->SetTopic(topic);
	dbUpdateChannel(chan);
	
	// send topic to connected clients
	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); ++i)
	{
		GetPublicKey((*i));

		// don't resend the topic to the client that set it in the first place
		if((*i)->PublicKey()!=m_ids[identityid].m_publickey && (*i)->JoinedChannels().find(channel)!=(*i)->JoinedChannels().end())
		{
			(*i)->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_TOPIC,m_ids[identityid].GetNick(),channel+" :"+chan->GetTopic()));
		}
	}
}

void IRCServer::SendMOTDLines(IRCClientConnection *client)
{
	client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_MOTDSTART,client->Nick(),":- "+m_servername+" Message of the Day -"));
	for(std::vector<std::string>::iterator i=m_motdlines.begin(); i!=m_motdlines.end(); i++)
	{
		client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_MOTD,client->Nick(),":- "+(*i)));
	}
	client->SendCommand(IRCCommandResponse::MakeCommand(m_servername,IRCCommandResponse::RPL_ENDOFMOTD,client->Nick(),":End of Message of the Day"));
}

void IRCServer::SendPrivateMessageToClients(const int identityid, const std::string &recipient, const std::string &encryptedmessage, const MessageType messagetype)
{

	std::string messcmd("");

	switch(messagetype)
	{
	case MessageType::MT_NOTICE:
		messcmd="NOTICE";
		break;
	case MessageType::MT_MESSAGE:
	default:
		messcmd="PRIVMSG";
		break;
	}

	LoadIdentity(identityid);

	// send message to recipient of private message
	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); ++i)
	{
		GetPublicKey((*i));

		if((*i)->PublicKey()==recipient)
		{
			RSAKeyPair rsa;
			std::string message("");
			//std::string idstr("");
			//StringFunctions::Convert(identityid,idstr);

			if(rsa.SetFromEncodedPrivateKey((*i)->RSAPrivateKey()))
			{
				if(rsa.Decrypt(encryptedmessage,message))
				{
					// C1: warn the local user if the sender is using a weak key.
					// We still deliver the message so the user is not silently cut off.
					int keybits=RSAKeyPair::GetKeyBitsFromEncodedKey(m_ids[identityid].m_publickey);
					if(keybits>0 && keybits<2048)
					{
						std::string bitsstr;
						StringFunctions::Convert(keybits,bitsstr);
						// Notify every locally-connected client that is the recipient of
						// the private message (normally exactly one client).
						if((*i)->IsConnected())
						{
							(*i)->SendCommand(IRCCommand(":"+m_servername+" NOTICE "+(*i)->Nick()+" :[SECURITY WARNING] "+m_ids[identityid].GetNick()+" sent this message using a "+bitsstr+"-bit RSA key.  This is cryptographically weak.  Ask them to upgrade FLIP or run /1024 "+m_ids[identityid].GetNick()+" before replying."));
						}
					}
					// Deliver the actual private message.
					(*i)->SendCommand(IRCCommand(":"+m_ids[identityid].GetNick()+" "+messcmd+" "+(*i)->Nick()+" :"+message));
				}
				else
				{
					m_log->Error("IRCServer::SendPrivateMessageToClients unable to decrypt private message");
				}
			}
			else
			{
				m_log->Error("IRCServer::SendPrivateMessageToClients unable to load private key into RSAKeyPair");
			}
		}

	}

	m_log->Debug("IRCServer::SendPrivateMessageToClients handled private message");
}

void IRCServer::SendJoinMessageToClients(const int identityid, const std::string &channel)
{
	//std::string idstr("");
	//StringFunctions::Convert(identityid,idstr);

	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); ++i)
	{
		GetPublicKey((*i));

		// don't send join message if the client is the one that sent the message
		if((*i)->PublicKey()!=m_ids[identityid].m_publickey && (*i)->JoinedChannels().find(channel)!=(*i)->JoinedChannels().end())
		{
			(*i)->SendCommand(IRCCommand(":"+m_ids[identityid].GetNick()+" JOIN "+channel));
		}
	}
}

void IRCServer::SendPartMessageToClients(const int identityid, const std::string &channel)
{
	//std::string idstr("");
	//StringFunctions::Convert(identityid,idstr);

	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); ++i)
	{
		GetPublicKey((*i));

		if((*i)->PublicKey()!=m_ids[identityid].m_publickey && (*i)->JoinedChannels().find(channel)!=(*i)->JoinedChannels().end())
		{
			(*i)->SendCommand(IRCCommand(":"+m_ids[identityid].GetNick()+" PART "+channel));
		}
	}
}

void IRCServer::SendNickChangeMessageToClients(const int identityid, const std::string &oldnick)
{
	// we can send to all connected clients, even the one chaning the nick
	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); ++i)
	{
		(*i)->SendCommand(IRCCommand(":"+oldnick+" NICK "+m_ids[identityid].GetNick()));
	}
}

const bool IRCServer::SetupClientSSL(IRCClientConnection::ssl_client_info &ssl, int socket)
{
	if(m_sslsetup==true)
	{
		int ret=0;
		std::string temp("");
		std::string dhprime("");
		Option option;

		option.Get("IRCSSLDHPrime",dhprime);

		mbedtls_entropy_init(&ssl.m_entropy);
		mbedtls_ctr_drbg_init(&ssl.m_ctr_drbg);
		ret=mbedtls_ctr_drbg_seed(&ssl.m_ctr_drbg,mbedtls_entropy_func,&ssl.m_entropy,0,0);
		if(ret!=0)
		{
			StringFunctions::Convert(ret,temp);
			m_log->Error("IRCServer::SetupClientSSL couldn't initialize ctr drbg - return value = "+temp);
			return false;
		}

		mbedtls_ssl_init(&ssl.m_ssl);
		mbedtls_ssl_config_init(&ssl.m_ssl_config);
		mbedtls_ssl_config_defaults(&ssl.m_ssl_config,MBEDTLS_SSL_IS_SERVER,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT);

		mbedtls_ssl_conf_endpoint(&ssl.m_ssl_config,MBEDTLS_SSL_IS_SERVER);
		mbedtls_ssl_conf_authmode(&ssl.m_ssl_config,MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_conf_rng(&ssl.m_ssl_config,mbedtls_ctr_drbg_random,&ssl.m_ctr_drbg);
		// C3: Require TLS 1.2 minimum.  mbedTLS MINOR_VERSION_3 == TLS 1.2.
		// This drops SSLv3, TLS 1.0, and TLS 1.1 which have known protocol flaws
		// (POODLE, BEAST, etc.).
		mbedtls_ssl_conf_min_version(&ssl.m_ssl_config,
		                             MBEDTLS_SSL_MAJOR_VERSION_3,
		                             MBEDTLS_SSL_MINOR_VERSION_3);
		// H2: Restrict to AEAD-only cipher suites (GCM).  This drops RC4, 3DES,
		// and CBC-mode suites which are vulnerable to BEAST / Lucky-13 attacks.
		// The list ends with 0 (sentinel required by mbedTLS).
		static const int secure_suites[] = {
			MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
			MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
			0
		};
		mbedtls_ssl_conf_ciphersuites(&ssl.m_ssl_config,secure_suites);
		//ssl_set_session(&ssl.m_ssl,&ssl.m_session);
		//memset(&ssl.m_session,0,sizeof(ssl.m_session));

		//ssl_set_ca_chain(&ssl.m_ssl,m_ssl.m_cert.next,0,0);
		mbedtls_ssl_conf_own_cert(&ssl.m_ssl_config,&m_ssl.m_cert,&m_ssl.m_pk);
		// mbedTLS 3.x: mbedtls_ssl_conf_dh_param removed; ECDHE suites do not need DHE params.
		
		//ssl_session_reset(&ssl.m_ssl);
		mbedtls_ssl_set_bio(&ssl.m_ssl,&socket,mbedtls_net_send,0,mbedtls_net_recv_timeout);

		mbedtls_ssl_setup(&ssl.m_ssl,&ssl.m_ssl_config);

		// we do the handshake in the client thread now because it blocks
		/*
		ret=ssl_handshake(&ssl.m_ssl);
		if(ret!=0)
		{
			StringFunctions::Convert(ret,temp);
			m_log->Error("IRCServer::SetupClientSSL couldn't handshake with client - return value = "+temp);
			return false;
		}
		*/

		return true;
	}

	return false;
}

const bool IRCServer::SetupServerSSL()
{
	if(m_sslsetup==false)
	{
		int ret=0;
		Option option;
		std::string sslcertificate("");
		std::string rsakey("");
		std::string rsapassword("");
		std::string temp("");

		option.Get("IRCSSLCertificate",sslcertificate);
		option.Get("IRCSSLRSAKey",rsakey);
		option.Get("IRCSSLRSAPassword",rsapassword);

		// mbedtls wants a \0 at the end of the certificate, so add it
		sslcertificate+='\0';
		memset(&m_ssl.m_cert,0,sizeof(mbedtls_x509_crt));
		ret=mbedtls_x509_crt_parse(&m_ssl.m_cert,(const unsigned char *)sslcertificate.c_str(),sslcertificate.size());
		if(ret!=0)
		{
			StringFunctions::Convert(ret,temp);
			m_log->Error("IRCServer::SetupServerSSL couldn't read certificate - return value = "+temp);
			return false;
		}

		// mbedtls wants a \0 at the end of the private key, so add it
		rsakey+='\0';
		mbedtls_pk_init(&m_ssl.m_pk);
		// mbedTLS 3.x: f_rng/p_rng args added for decrypting password-protected keys.
		mbedtls_entropy_init(&m_ssl.m_entropy);
		mbedtls_ctr_drbg_init(&m_ssl.m_ctr_drbg);
		mbedtls_ctr_drbg_seed(&m_ssl.m_ctr_drbg,mbedtls_entropy_func,&m_ssl.m_entropy,NULL,0);
		ret=mbedtls_pk_parse_key(&m_ssl.m_pk,(const unsigned char *)rsakey.c_str(),rsakey.size(),(const unsigned char *)rsapassword.c_str(),rsapassword.size(),mbedtls_ctr_drbg_random,&m_ssl.m_ctr_drbg);
		if(ret!=0)
		{
			StringFunctions::Convert(ret,temp);
			m_log->Error("IRCServer::SetupServerSSL couldn't read RSA key - return value = "+temp);
			mbedtls_x509_crt_free(&m_ssl.m_cert);
			mbedtls_pk_free(&m_ssl.m_pk);
			return false;
		}

		m_sslsetup=true;
	}

	return m_sslsetup;
}

void IRCServer::ShutdownServerSSL()
{
	if(m_sslsetup==true)
	{
		mbedtls_x509_crt_free(&m_ssl.m_cert);
		mbedtls_pk_free(&m_ssl.m_pk);

		m_sslsetup=false;
	}
}

void IRCServer::Start()
{
	Option option;
	std::string temp("");
	std::vector<std::string> listenaddresses;
	std::string bindaddresses;
	std::string listenport;
	std::string listenportssl;
	bool listenunsecure=false;
	bool listenssl=false;
	m_sslsetup=false;

	m_datestarted.SetNowUTC();

	// C9/C10: load configurable limits from the options database.
	std::string maxclientsstr("50");
	option.Get("IRCMaxClients",maxclientsstr);
	StringFunctions::Convert(maxclientsstr,m_maxclients);
	if(m_maxclients<=0) { m_maxclients=50; }
	option.Get("IRCPassword",m_ircpassword);

	option.GetBool("IRCListenUnsecure",listenunsecure);
	option.GetBool("IRCListenSSL",listenssl);
	option.Get("IRCListenPort",listenport);
	option.Get("IRCSSLListenPort",listenportssl);
	option.Get("IRCBindAddresses",bindaddresses);
	option.Get("FLIPServiceNick",m_flipservicenick);

	m_flipservice.SetNick(m_flipservicenick);
	m_flipservice.SetGetIdentityFunctions(
		[&](const std::string &nick, int &identityid) -> const bool { return GetIdentityIDFromNick(nick,identityid); },
		[&](const std::string &ssk, int &identityid) -> const bool { return GetIdentityIDFromSSK(ssk,identityid); });
	m_flipservice.SetValidateIdentityFunctions(
		[&](const int identityid) -> const bool { return ValidateIdentity(identityid); },
		[&](const int identityid) -> const bool { return InvalidateIdentity(identityid); });

	ReloadMOTD();

	StringFunctions::Split(bindaddresses,",",listenaddresses);

	for(std::vector<std::string>::iterator i=listenaddresses.begin(); i!=listenaddresses.end(); i++)
	{
		int sock=0;
		int rval=0;
		struct addrinfo hint,*result,*current;
		result=current=0;

		memset(&hint,0,sizeof(hint));
		hint.ai_socktype=SOCK_STREAM;
		hint.ai_protocol=IPPROTO_TCP;
		hint.ai_flags=AI_PASSIVE;

		m_log->Trace("IRCServer::Start getting address info for "+(*i));

		// bind to unsecure port
		if(listenunsecure==true)
		{
			rval=getaddrinfo((*i).c_str(),listenport.c_str(),&hint,&result);
			if(rval==0)
			{
				for(current=result; current!=0; current=current->ai_next)
				{
					m_log->Debug("IRCServer::Start trying to create socket, bind and listen on "+(*i)+" unsecure port "+listenport);

					sock=socket(current->ai_family,current->ai_socktype,current->ai_protocol);
					if(sock!=-1)
					{
						#ifndef _WIN32
						const char optval=1;
						setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));
						#endif
						if(bind(sock,current->ai_addr,current->ai_addrlen)==0)
						{
							if(listen(sock,10)==0)
							{
								m_log->Info("IRCServer::Start started listening on "+(*i)+" unsecure port "+listenport);
								m_listensockets.push_back(sock);
							}
							else
							{
								m_log->Error("IRCServer::Start socket listen failed on "+(*i)+" unsecure port "+listenport);
								#ifdef _WIN32
								closesocket(sock);
								#else
								close(sock);
								#endif
							}
						}
						else
						{
							m_log->Error("IRCServer::Start socket bind failed on "+(*i)+" unsecure port "+listenport);
							#ifdef _WIN32
							closesocket(sock);
							#else
							close(sock);
							#endif
						}
					}
					else
					{
						m_log->Error("IRCServer::Start couldn't create socket on "+(*i));
					}

				}
			}
			if(result)
			{
				freeaddrinfo(result);
			}
		}
		if(listenssl==true && SetupServerSSL()==true)
		{
			rval=getaddrinfo((*i).c_str(),listenportssl.c_str(),&hint,&result);
			if(rval==0)
			{
				for(current=result; current!=0; current=current->ai_next)
				{
					m_log->Debug("IRCServer::Start trying to create socket, bind and listen on "+(*i)+" SSL port "+listenportssl);

					sock=socket(current->ai_family,current->ai_socktype,current->ai_protocol);
					if(sock!=-1)
					{
						#ifndef _WIN32
						const char optval=1;
						setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval));
						#endif
						if(bind(sock,current->ai_addr,current->ai_addrlen)==0)
						{
							if(listen(sock,10)==0)
							{
								m_log->Info("IRCServer::Start started listening on "+(*i)+" SSL port "+listenportssl);
								m_ssllistensockets.push_back(sock);
							}
							else
							{
								m_log->Error("IRCServer::Start socket listen failed on "+(*i)+" SSL port "+listenportssl);
								#ifdef _WIN32
								closesocket(sock);
								#else
								close(sock);
								#endif
							}
						}
						else
						{
							m_log->Error("IRCServer::Start socket bind failed on "+(*i)+" SSL port "+listenportssl);
							#ifdef _WIN32
							closesocket(sock);
							#else
							close(sock);
							#endif
						}
					}
					else
					{
						m_log->Error("IRCServer::Start couldn't create socket on "+(*i));
					}

				}
			}
			if(result)
			{
				freeaddrinfo(result);
			}
		}
	}
	if(m_listensockets.size()==0 && m_ssllistensockets.size()==0)
	{
		m_log->Fatal("IRCServer::Start couldn't start listening on any interfaces");
	}
}

void IRCServer::Shutdown()
{
	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); i++)
	{
		(*i)->Disconnect();
	}
	m_clients.clear();

	for(std::vector<int>::iterator i=m_listensockets.begin(); i!=m_listensockets.end(); i++)
	{
		#ifdef _WIN32
		closesocket((*i));
		#else
		close((*i));
		#endif
	}
	m_listensockets.clear();

	m_log->Debug("IRCServer::Shutdown completed");

}

void IRCServer::Update(const unsigned long ms)
{
	int rval=0;
	fd_set readfs;
	fd_set writefs;
	struct timeval tv;
	int highsock=0;

	// delete any clients that are disconnected
	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); )
	{
		if((*i)->IsConnected())
		{
			// send keepalive message if this client hasn't sent anything in the last 10 minutes
			DateTime past;
			past.Add(0,-10,0,0,0,0);
			if((*i)->LastActivity()<past)
			{
				std::string chanstring("");
				std::map<std::string,std::string> params;
				StringFunctions::Convert((*i)->LocalDBID(),params["localidentityid"]);
				(*i)->LastActivity().SetNowUTC();
				
				for(std::set<std::string>::const_iterator j=(*i)->JoinedChannels().begin(); j!=(*i)->JoinedChannels().end(); j++)
				{
					if(chanstring!="")
					{
						chanstring+=" ";
					}
					chanstring+=(*j);
				}
				params["channels"]=chanstring;
				params["nick"]=(*i)->Nick();

				DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_KEEPALIVE,params));
			}
			i++;
		}
		else
		{
			std::map<std::string,std::string> params;
			params["nick"]=(*i)->Nick();
			StringFunctions::Convert((*i)->LocalDBID(),params["localidentityid"]);

			//send part to all joined channels and remove from channel ids
			if((*i)->PeerDBID()>0)
			{
				for(std::set<std::string>::const_iterator j=(*i)->JoinedChannels().begin(); j!=(*i)->JoinedChannels().end(); j++)
				{
					SendPartMessageToClients((*i)->PeerDBID(),(*j));
					m_idchannels[(*j)].erase((*i)->PeerDBID());
				}
			}

			DispatchFLIPEvent(FLIPEvent(FLIPEvent::EVENT_IRC_USERQUIT,params));

			m_log->Info("IRCServer::Update client connection deleted");
			delete (*i);
			i=m_clients.erase(i);
		}
	}

	// process any queued events
	for(std::map<int,idinfo>::iterator i=m_ids.begin(); i!=m_ids.end(); i++)
	{
		DateTime now;
		DateTime xsecondsago;
		xsecondsago.Add(-30,0,0,0,0,0);
		if((*i).second.m_messagequeue.size()>0)
		{
			std::set<idinfo::messagequeueitem,idinfo::messagequeuecompare>::iterator mi=(*i).second.m_messagequeue.begin();
			while(mi!=(*i).second.m_messagequeue.end() && ((*mi).m_edition<=(*i).second.m_lastdayedition[(*mi).m_insertday] || (*mi).m_arrivaltime<xsecondsago))
			{
				ProcessFLIPEvent((*i).first,(*mi).m_message);
				(*i).second.m_messagequeue.erase(mi);
				// gcc doesn't like assigning an iterator when erasing, so we have to do it this way
				mi=(*i).second.m_messagequeue.begin();
			}
		}
	}

	tv.tv_sec=ms/1000;
	tv.tv_usec=(ms%1000)*1000;

	FD_ZERO(&readfs);
	FD_ZERO(&writefs);

	for(std::vector<int>::iterator i=m_listensockets.begin(); i!=m_listensockets.end(); i++)
	{
		FD_SET((*i),&readfs);
		highsock=(std::max)((*i),highsock);
	}
	for(std::vector<int>::iterator i=m_ssllistensockets.begin(); i!=m_ssllistensockets.end(); i++)
	{
		FD_SET((*i),&readfs);
		highsock=(std::max)((*i),highsock);
	}

	// see if data is waiting on any of the sockets
	rval=select(highsock+1,&readfs,&writefs,0,&tv);

	if(rval>0)
	{
		// check for new connections on unsecure sockets
		for(std::vector<int>::iterator i=m_listensockets.begin(); i!=m_listensockets.end(); i++)
		{
			if(FD_ISSET((*i),&readfs))
			{
				int newsock=0;
				struct sockaddr_storage addr;
				socklen_t addrlen=sizeof(addr);
				newsock=accept((*i),(struct sockaddr *)&addr,&addrlen);
				if(newsock!=-1)
				{
					// C9: enforce per-configured maximum client count.
					if((int)m_clients.size()>=m_maxclients)
					{
						m_log->Warn("IRCServer::Update connection limit reached, rejecting new unsecure client");
						#ifdef _WIN32
						closesocket(newsock);
						#else
						close(newsock);
						#endif
					}
					else
					{
						m_log->Info("IRCServer::Update new client connected on unsecure socket");
						m_clients.push_back(new IRCClientConnection(newsock,this,IRCClientConnection::CON_UNSECURE,0));
					}
				}
			}
		}

		// check for new connectiosn on SSL sockets
		for(std::vector<int>::iterator i=m_ssllistensockets.begin(); i!=m_ssllistensockets.end(); i++)
		{
			if(FD_ISSET((*i),&readfs))
			{
				int newsock=0;
				struct sockaddr_storage addr;
				socklen_t addrlen=sizeof(addr);
				newsock=accept((*i),(struct sockaddr *)&addr,&addrlen);
				if(newsock!=-1)
				{
					// C9: enforce per-configured maximum client count.
					if((int)m_clients.size()>=m_maxclients)
					{
						m_log->Warn("IRCServer::Update connection limit reached, rejecting new SSL client");
						#ifdef _WIN32
						closesocket(newsock);
						#else
						close(newsock);
						#endif
					}
					else
					{
						IRCClientConnection::ssl_client_info *ssl=new IRCClientConnection::ssl_client_info;
						memset(ssl,0,sizeof(IRCClientConnection::ssl_client_info));
						if(ssl && SetupClientSSL(*ssl,newsock))
						{
							m_log->Info("IRCServer::Update new client connected on SSL socket");
							m_clients.push_back(new IRCClientConnection(newsock,this,IRCClientConnection::CON_SSL,ssl));
						}
						else
						{
							m_log->Error("IRCServer::Update couldn't setup SSL connection");
							if(ssl)
							{
								delete ssl;
							}
						}
					}
				}
			}
		}
	}

	for(std::vector<IRCClientConnection *>::iterator i=m_clients.begin(); i!=m_clients.end(); i++)
	{
		(*i)->HandleReceivedData();
	}

}

const bool IRCServer::ValidateIdentity(const int identityid)
{
	SQLite3DB::Statement st=m_db->Prepare("UPDATE tblIdentity SET Validated=1 WHERE IdentityID=?;");
	st.Bind(0,identityid);
	st.Step();

	if(m_ids.find(identityid)!=m_ids.end())
	{
		FindAndResolveNickCollision(identityid,m_ids[identityid].m_basenick,true);
	}
	return true;
}

const bool IRCServer::InvalidateIdentity(const int identityid)
{
	SQLite3DB::Statement st=m_db->Prepare("UPDATE tblIdentity SET Validated=0 WHERE IdentityID=?;");
	st.Bind(0,identityid);
	st.Step();

	if(m_ids.find(identityid)!=m_ids.end())
	{
		FindAndResolveNickCollision(identityid,m_ids[identityid].m_basenick,true);
	}
	return true;
}

IRCChannel* IRCServer::GetChannel(const std::string& name)
{
	if(m_channels.find(name)==m_channels.end())
	{
		IRCChannel* chan = new IRCChannel();
		if(chan->SetName(name))
		{
			dbAddChannel(chan);
			m_channels[name] = chan;
			return chan;
		}
		else
		{
			return NULL;
		}
	}
	else
	{
		return m_channels[name];
	}
}
