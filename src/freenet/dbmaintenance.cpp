#include "dbmaintenance.h"

DBMaintenance::DBMaintenance(FreenetConnection *connection):IPeriodicProcessor(connection)
{
	m_last6hourmaintenance.Add(0,-15,-5);
	m_last1daymaintenance.Add(0,-20,-23);
}

DBMaintenance::~DBMaintenance()
{

}

void DBMaintenance::Do1DayMaintenance()
{
	DateTime yesterday;
	DateTime tendaysago;

	yesterday.Add(0,0,0,-1);
	tendaysago.Add(0,0,0,-10);

	m_db->Execute("BEGIN;");

	SQLite3DB::Statement st=m_db->Prepare("DELETE FROM tblIdentity WHERE ((DateAdded<? AND LastSeen IS NULL) OR LastSeen<?) AND Ignored=0 AND Validated=0;");
	st.Bind(0,tendaysago.Format("%Y-%m-%d"));
	st.Bind(1,tendaysago.Format("%Y-%m-%d"));
	st.Step();

	st=m_db->Prepare("DELETE FROM tblAnnounceIndex WHERE Date<?;");
	st.Bind(0,yesterday.Format("%Y-%m-%d"));
	st.Step();

	st=m_db->Prepare("DELETE FROM tblIdentityEdition WHERE Date<?;");
	st.Bind(0,yesterday.Format("%Y-%m-%d"));
	st.Step();

	st=m_db->Prepare("DELETE FROM tblInsertedMessageIndex WHERE Date<?;");
	st.Bind(0,yesterday.Format("%Y-%m-%d"));
	st.Step();

	st=m_db->Prepare("DELETE FROM tblRetrievedMessageIndex WHERE Date<?;");
	st.Bind(0,yesterday.Format("%Y-%m-%d"));
	st.Step();

	st=m_db->Prepare("DELETE FROM tblLocalIdentityInsert WHERE Date<?;");
	st.Bind(0,yesterday.Format("%Y-%m-%d"));
	st.Step();

	m_db->Execute("COMMIT;");

	// SQLite3 3.18 introducted PRAGMA optimize - see what PRAGMA optimize recommends and write it in the log
	if(SQLITE_VERSION_NUMBER >= 3018000)
	{
		SQLite3DB::Statement st=m_db->Prepare("PRAGMA optimize(-1);");
		if(st.Step())
		{
			while(st.RowReturned())
			{
				std::string res("");
				st.ResultText(0,res);
				m_log->Info("PeriodicDBMaintenance::Do1DayMaintenance PRAGMA optimize(-1); recommends running "+res);
				st.Step();
			}
			m_log->Info("PeriodicDBMaintenance::Do1DayMaintenance end of PRAGMA optimize(-1); recommendations");
		}
		else
		{
			m_log->Error("PeriodicDBMaintenance::Do1DayMaintenance couldn't execute PRAGMA optimize(-1);");
		}
		st.Finalize();
	}

	m_log->Error("DBMaintenance::Do1DayMaintenance");
}

void DBMaintenance::Do6HoursMaintenance()
{


}

void DBMaintenance::Process()
{
	DateTime now;
	DateTime sixhoursago;
	DateTime onedayago;

	sixhoursago.Add(0,0,-6);
	onedayago.Add(0,0,0,-1);

	if(m_last6hourmaintenance<sixhoursago)
	{
		Do6HoursMaintenance();
		m_last6hourmaintenance.SetNowUTC();
	}
	if(m_last1daymaintenance<onedayago)
	{
		Do1DayMaintenance();
		m_last1daymaintenance.SetNowUTC();
	}
}
