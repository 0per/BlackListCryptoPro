#include "Request.h"

Request::Request(string operatorName, string inn, string ogrn, string email)
{
	tm ltm;
	char buff[32]="x00";

	request.clear();
	request += "<?xml version=\"1.0\" encoding=\"windows-1251\"?>\n";
	request += "<request>\n";
	request += "<requestTime>";
	const time_t now = time(0);
	localtime_s(&ltm,&now);
	strftime(buff,sizeof(buff),"%Y-%m-%dT%H:%M:00.000+04:00",&ltm); // да и хрен бы с ними с секундами
	request += buff;
	request += "</requestTime>\n";
	request += "<operatorName>";
	request += "<![CDATA[" + operatorName + "]]>";
	request += "</operatorName>\n";
	request += "<inn>";
	request += inn;
	request += "</inn>\n";
	request += "<ogrn>";
	request += ogrn;
	request += "</ogrn>\n";
	request += "<email>";
	request += email;
	request += "</email>\n";
	request += "</request>";
}


Request::~Request(void)
{
}
