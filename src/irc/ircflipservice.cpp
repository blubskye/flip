#include "ircflipservice.h"
#include "../stringfunctions.h"
#include "../datetime.h"

IRCFLIPService::IRCFLIPService():m_nick(""),m_connected(false)
{

}

const bool IRCFLIPService::HandleCommand(const IRCCommand &command, IRCClientConnection *client)
{
	bool handled=false;

	if(command.GetParameters().size()>1)
	{
		std::vector<std::string> commandparts;
		StringFunctions::Split(command.GetParameters()[1]," ",commandparts);

		if(commandparts.size()>0)
		{
			StringFunctions::LowerCase(commandparts[0],commandparts[0]);
		}

		if(commandparts[0]=="help")
		{
			if(commandparts.size()==2)
			{
				SendHelp(client,command.GetParameters()[1]);
			}
			else
			{
				SendHelp(client,"");
			}
			handled=true;
		}
		else if(commandparts[0]=="status")
		{
			handled=HandleStatus(client,command.GetParameters()[1]);
		}
		else if(commandparts[0]=="options")
		{
			handled=HandleOptions(client,command.GetParameters()[1]);
		}
		else if(commandparts[0]=="peer")
		{
			handled=HandlePeer(client,command.GetParameters()[1]);
		}

		if(handled==false)
		{
			SendHelp(client,"");
		}

	}
	else
	{
		SendHelp(client,"");
	}

	return true;
}

const bool IRCFLIPService::HandleOptions(IRCClientConnection *client, const std::string &command)
{
	std::string commandprefix=":"+m_nick+" NOTICE "+client->Nick()+" :";

	bool handled=false;
	std::vector<std::string> commandparts;
	StringFunctions::Split(command," ",commandparts);

	if(commandparts.size()>1)
	{
		StringFunctions::LowerCase(commandparts[1],commandparts[1]);

		if(commandparts[1]=="show" && commandparts.size()==2)
		{
			client->SendCommand(IRCCommand(commandprefix+"\x02***** FLIP Options *****\x0f"));
			SQLite3DB::Statement st=m_db->Prepare("SELECT Option,OptionValue,OptionDescription,ValidValues,Section FROM tblOption ORDER BY SortOrder;");
			st.Step();
			while(st.RowReturned())
			{
				std::string option("");
				std::string optionvalue("");
				std::string description("");
				std::string validvalues("");
				std::string section("");

				st.ResultText(0,option);
				st.ResultText(1,optionvalue);
				st.ResultText(2,description);
				st.ResultText(3,validvalues);
				st.ResultText(4,section);

				SendOption(client,option,optionvalue,description,validvalues);

				st.Step();
			}
			handled=true;
			client->SendCommand(IRCCommand(commandprefix+"\x02***** End of Options *****\x0f"));
		}
		else if(commandparts[1]=="show" && commandparts.size()==3)
		{
			client->SendCommand(IRCCommand(commandprefix+"\x02***** FLIP Options *****\x0f"));
			SQLite3DB::Statement st=m_db->Prepare("SELECT Option,OptionValue,OptionDescription,ValidValues FROM tblOption WHERE Option=?;");
			st.Bind(0,commandparts[2]);
			st.Step();
			if(st.RowReturned())
			{
				std::string option("");
				std::string optionvalue("");
				std::string description("");
				std::string validvalues("");
				std::string section("");

				st.ResultText(0,option);
				st.ResultText(1,optionvalue);
				st.ResultText(2,description);
				st.ResultText(3,validvalues);
				st.ResultText(4,section);

				SendOption(client,option,optionvalue,description,validvalues);
			}
			else
			{
				SendOption(client,"Option "+commandparts[2]+" not found","","","");
			}
			handled=true;
			client->SendCommand(IRCCommand(commandprefix+"\x02***** End of Options *****\x0f"));
		}
		else if(commandparts[1]=="set" && commandparts.size()>=4)
		{
			std::string value=commandparts[3];
			for(int i=4; i<commandparts.size(); ++i)
			{
				value+=" "+commandparts[i];
			}

			client->SendCommand(IRCCommand(commandprefix+"\x02***** FLIP Options *****\x0f"));

			SQLite3DB::Statement st=m_db->Prepare("SELECT 1 FROM tblOption WHERE Option=?;");
			st.Bind(0,commandparts[2]);
			st.Step();
			if(st.RowReturned())
			{
				std::vector<char> literalchars;
				std::vector<char> replacechars;

				literalchars.push_back('\\');
				literalchars.push_back('r');
				literalchars.push_back('n');

				replacechars.push_back('\\');
				replacechars.push_back('\r');
				replacechars.push_back('\n');

				value=StringFunctions::UnEscape(value,'\\',literalchars,replacechars);

				st.Finalize();
				st=m_db->Prepare("UPDATE tblOption SET OptionValue=? WHERE Option=?;");
				st.Bind(0,value);
				st.Bind(1,commandparts[2]);
				st.Step();
				st.Finalize();

				client->SendCommand(IRCCommand(commandprefix+"\x02"+commandparts[2]+"\x0f set"));
			}
			else
			{
				SendOption(client,"Option "+commandparts[2]+" not found","","","");
			}

			handled=true;
			client->SendCommand(IRCCommand(commandprefix+"\x02***** End of Options *****\x0f"));
		}
	}

	return handled;
}

const bool IRCFLIPService::HandlePeer(IRCClientConnection *client, const std::string &command)
{
	std::string commandprefix=":"+m_nick+" NOTICE "+client->Nick()+" :";

	bool handled=false;
	std::vector<std::string> commandparts;
	StringFunctions::Split(command," ",commandparts);

	if(commandparts.size()==3 && (commandparts[1]=="validate" || commandparts[1]=="invalidate"))
	{
		int identityid=-1;
		if(GetIdentityIDFromNick(commandparts[2],identityid)==false)
		{
			GetIdentityIDFromSSK(commandparts[2],identityid);
		}

		if(identityid>-1)
		{
			if(commandparts[1]=="validate")
			{
				ValidateIdentity(identityid);
				client->SendCommand(IRCCommand(commandprefix+"\x02"+commandparts[2]+"\x0f validated"));
			}
			else
			{
				InvalidateIdentity(identityid);
				client->SendCommand(IRCCommand(commandprefix+"\x02"+commandparts[2]+"\x0f invalidated"));
			}
		}
		else
		{
			client->SendCommand(IRCCommand(commandprefix+"\x02Nick or SSK not found\x0f"));
		}

		handled=true;
	}
	else if(commandparts.size()==3 && commandparts[1]=="add")
	{
		if(commandparts[2].size()>20 && commandparts[2].substr(0,4)=="SSK@" && commandparts[2][commandparts.size()-1]=='/')
		{
			DateTime now;
			SQLite3DB::Statement st=m_db->Prepare("INSERT OR IGNORE INTO tblIdentity(PublicKey,DateAdded,AddedMethod) VALUES(?,?,'Added manually');");
			st.Bind(0,commandparts[2]);
			st.Bind(1,now.Format("%Y-%m-%d %H:%M:%S"));
			st.Step();
			client->SendCommand(IRCCommand(commandprefix+"\x02"+commandparts[2]+"\x0f added"));
		}
		else
		{
			client->SendCommand(IRCCommand(commandprefix+"\x02SSK not valid\x0f"));
		}

		handled=true;
	}
	else if((commandparts.size()==2 || commandparts.size()==3) && commandparts[1]=="show")
	{
		SQLite3DB::Statement st;
		if(commandparts.size()==2)
		{
			st=m_db->Prepare("SELECT IdentityID, PublicKey, Name, DateAdded, AddedMethod, LastSeen, Ignored, Validated FROM tblIdentity ORDER BY PublicKey COLLATE NOCASE;");
		}
		else
		{
			int identityid=-1;
			if(GetIdentityIDFromNick(commandparts[2],identityid)==false)
			{
				GetIdentityIDFromSSK(commandparts[2],identityid);
			}
			st=m_db->Prepare("SELECT IdentityID, PublicKey, Name, DateAdded, AddedMethod, LastSeen, Ignored, Validated FROM tblIdentity WHERE IdentityID=? ORDER BY PublicKey COLLATE NOCASE;");
			st.Bind(0,identityid);
		}
		st.Step();
		if(st.RowReturned())
		{
			while(st.RowReturned())
			{
				peerinfo peer;
				int tempint=-1;

				st.ResultInt(0,peer.m_identityid);
				st.ResultText(1,peer.m_publickey);
				st.ResultText(2,peer.m_name);
				st.ResultText(3,peer.m_dateadded);
				st.ResultText(4,peer.m_addedmethod);
				st.ResultText(5,peer.m_lastseen);
				st.ResultInt(6,tempint);
				if(tempint==1)
				{
					peer.m_ignored=true;
				}
				else
				{
					peer.m_ignored=false;
				}
				st.ResultInt(7,tempint);
				if(tempint==1)
				{
					peer.m_validated=true;
				}
				else
				{
					peer.m_validated=false;
				}

				SendPeer(client,peer);

				st.Step();
			}
		}
		else
		{
			client->SendCommand(IRCCommand(commandprefix+"\x02Peer not found\x0f"));
		}

		handled=true;
	}
	else if(commandparts.size()==3 && (commandparts[1]=="ignore" || commandparts[1]=="unignore"))
	{
		int identityid=-1;
		if(GetIdentityIDFromNick(commandparts[2],identityid)==false)
		{
			GetIdentityIDFromSSK(commandparts[2],identityid);
		}
		if(identityid>-1)
		{
			SQLite3DB::Statement st=m_db->Prepare("UPDATE tblIdentity SET Ignored=? WHERE IdentityID=?;");
			if(commandparts[1]=="ignore")
			{
				st.Bind(0,1);
			}
			else
			{
				st.Bind(0,0);
			}
			st.Bind(1,identityid);
			st.Step();
			client->SendCommand(IRCCommand(commandprefix+"\x02Peer updated\x0f"));
		}
		else
		{
			client->SendCommand(IRCCommand(commandprefix+"\x02Peer not found\x0f"));
		}

		handled=true;
	}

	return handled;
}

const bool IRCFLIPService::HandleStatus(IRCClientConnection *client, const std::string &command)
{
	std::string commandprefix=":"+m_nick+" NOTICE "+client->Nick()+" :";

	bool handled=false;
	std::vector<std::string> commandparts;
	StringFunctions::Split(command," ",commandparts);

	if(commandparts.size()==1)
	{
		client->SendCommand(IRCCommand(commandprefix+"\x02***** FLIP Status *****\x0f"));

		client->SendCommand(IRCCommand(commandprefix+"FCP Connection : "+(m_connected==true ? "CONNECTED" : "DISCONNECTED")));

		client->SendCommand(IRCCommand(commandprefix+"\x02***** End of Status *****\x0f"));
		handled=true;
	}

	return handled;
}

void IRCFLIPService::SendHelp(IRCClientConnection *client, const std::string &command)
{
	std::string commandprefix=":"+m_nick+" NOTICE "+client->Nick()+" :";
	std::string com("");
	StringFunctions::LowerCase(command,com);

	client->SendCommand(IRCCommand(commandprefix+"\x02***** FLIP Service Help *****\x0f"));

	if(com=="help options")
	{
		client->SendCommand(IRCCommand(commandprefix+"Help for \x02options\x0f"));
		client->SendCommand(IRCCommand(commandprefix+"Views or sets various program options"));
		client->SendCommand(IRCCommand(commandprefix+"\x02options show [option]          \x0f Shows all options and their values or just one specific option and its value"));
		client->SendCommand(IRCCommand(commandprefix+"\x02options set <option> <value>   \x0f Sets the value for the specified option"));
		client->SendCommand(IRCCommand(commandprefix+"\x02                               \x0f Use \\r or \\n for a carriage return or line feed within the option value"));
		client->SendCommand(IRCCommand(commandprefix+"\x02                               \x0f Escape a single \\ by typing \\\\ within the option value (Escape only necessary when followed by r or n)"));
	}
	else if(com=="help status")
	{
		client->SendCommand(IRCCommand(commandprefix+"Help for \x02status\x0f"));
		client->SendCommand(IRCCommand(commandprefix+"Shows status of FLIP"));
		client->SendCommand(IRCCommand(commandprefix+"\x02status                          \x0f Shows status of FLIP"));
	}
	else if(com=="help peer")
	{
		client->SendCommand(IRCCommand(commandprefix+"Help for \x02peer\x0f"));
		client->SendCommand(IRCCommand(commandprefix+"Manages peer identities"));
		client->SendCommand(IRCCommand(commandprefix+"Validated peer identities are preferred to retain their chosen nick when nick collisions occur"));
		client->SendCommand(IRCCommand(commandprefix+"SSKs may be used when a peer isn't currently connected"));
		client->SendCommand(IRCCommand(commandprefix+"SSKs must be a full valid Freenet SSK that starts with SSK@ and ends with /"));
		client->SendCommand(IRCCommand(commandprefix+"\x02validate <nick | ssk>      \x0fValidates a peer identity"));
		client->SendCommand(IRCCommand(commandprefix+"\x02invalidate <nick | ssk>    \x0fInvalidates a peer identity"));
		client->SendCommand(IRCCommand(commandprefix+"\x02"+"add <ssk>                  \x0f"+"Adds a new peer manually"));
		client->SendCommand(IRCCommand(commandprefix+"\x02show [nick | ssk]          \x0fShows informaton about all peers or specific peer"));
		client->SendCommand(IRCCommand(commandprefix+"\x02ignore <nick | ssk>        \x0fIgnores a nick or SSK"));
		client->SendCommand(IRCCommand(commandprefix+"\x02                           \x0fYou must restart FLIP for ignore to take affect"));
		client->SendCommand(IRCCommand(commandprefix+"\x02unignore <nick | ssk>      \x0fRemoves ignore from nick or SSK"));
		client->SendCommand(IRCCommand(commandprefix+"\x02                           \x0fYou must restart FLIP for unignore to take affect"));
	}
	else
	{
		client->SendCommand(IRCCommand(commandprefix+"The FLIP Service is used to control various aspects of FLIP"));
		client->SendCommand(IRCCommand(commandprefix+"Usage:"));
		client->SendCommand(IRCCommand(commandprefix+"/msg "+m_nick+" \x02"+"command\x0f [arguments]"));
		client->SendCommand(IRCCommand(commandprefix+"Arguments within [] are optional.  Arguments within <> are required."));
		client->SendCommand(IRCCommand(commandprefix+"Available commands:"));
		client->SendCommand(IRCCommand(commandprefix+"\x02help [command]           \x0f Show general help or help on a specific command"));
		client->SendCommand(IRCCommand(commandprefix+"\x02status                   \x0f Shows status of FLIP"));
		client->SendCommand(IRCCommand(commandprefix+"\x02options                  \x0f Manage FLIP program options"));
		client->SendCommand(IRCCommand(commandprefix+"\x02peer                     \x0f Manage peer identities"));
	}

	client->SendCommand(IRCCommand(commandprefix+"\x02***** End of Help *****\x0f"));

}

void IRCFLIPService::SendOption(IRCClientConnection *client, const std::string &option,const std::string &optionvalue,const std::string &description,const std::string &validvalues)
{
	std::string commandprefix=":"+m_nick+" NOTICE "+client->Nick()+" :";

	std::string com(commandprefix);
	com+="\x02"+option+"\x0f";

	if(optionvalue!="")
	{
		std::vector<std::string> valueparts;
		StringFunctions::Split(optionvalue,"\r\n",valueparts);

		for(int i=0; i<valueparts.size(); ++i)
		{
			if(i==0)
			{
				std::vector<char> spaces((std::max)(5,(int)(30-option.size())),' ');
				com+=std::string(spaces.begin(),spaces.end());
				com+=valueparts[i];
			}
			else
			{
				com=commandprefix+valueparts[i];
			}
			client->SendCommand(com);
		}
	}
	else
	{
		client->SendCommand(IRCCommand(com));
	}

	if(validvalues!="")
	{
		std::vector<std::string> vals;
		StringFunctions::Split(validvalues,"|",vals);
		com=commandprefix+"Valid values : ";
		for(int i=1; i<vals.size(); i+=2)
		{
			if(i>1)
			{
				com+=", ";
			}
			com+=vals[i];
		}
		client->SendCommand(IRCCommand(com));
	}
	if(description!="")
	{
		client->SendCommand(IRCCommand(commandprefix+description));
	}
	client->SendCommand(IRCCommand(commandprefix+" "));
}

void IRCFLIPService::SendPeer(IRCClientConnection *client, const peerinfo &peer)
{
	std::string commandprefix=":"+m_nick+" NOTICE "+client->Nick()+" :";

	client->SendCommand(IRCCommand(commandprefix+peer.m_publickey));
	client->SendCommand(IRCCommand(commandprefix+"Name : "+peer.m_name));
	client->SendCommand(IRCCommand(commandprefix+"Added : "+peer.m_dateadded+"    Method : "+peer.m_addedmethod));
	client->SendCommand(IRCCommand(commandprefix+"Last Seen : "+peer.m_lastseen+"     Ignored : "+(peer.m_ignored ? "Yes" : "No ")+"    Validated : "+(peer.m_validated ? "Yes" : "No ")));

	client->SendCommand(IRCCommand(commandprefix+" "));
}

void IRCFLIPService::SetNick(const std::string &nick)
{
	m_nick=nick;
}
