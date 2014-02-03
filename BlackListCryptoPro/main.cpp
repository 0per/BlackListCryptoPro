#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>

using namespace std;

#define _WINSOCKAPI_ // Не включать в windows.h winsock.h иначе глючит gSOAP
#include <windows.h>
#include "soapH.h"
SOAP_NMAC struct Namespace namespaces[] =
{
	{"SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/", "http://www.w3.org/*/soap-envelope", NULL},
	{"SOAP-ENC", "http://schemas.xmlsoap.org/soap/encoding/", "http://www.w3.org/*/soap-encoding", NULL},
	{"xsi", "http://www.w3.org/2001/XMLSchema-instance", "http://www.w3.org/*/XMLSchema-instance", NULL},
	{"xsd", "http://www.w3.org/2001/XMLSchema", "http://www.w3.org/*/XMLSchema", NULL},
	{"ns1", "http://vigruzki.rkn.gov.ru/OperatorRequest/", NULL, NULL},
	{NULL, NULL, NULL, NULL}
};

#include <cryptuiapi.h>
#include <WinCryptEx.h> // wincrypt.h - включается внутри
#include <cades.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")

// Библиотека json используется для чтения конфигурации
#include <json/json.h>
#include <algorithm>

#ifdef _DEBUG
#pragma comment(lib, "../Debug/lib_json.lib")
#else
#pragma comment(lib, "../Release/lib_json.lib")
#endif


#define TIME_UPDATE 60000 * 30 //в минутах 30 мин
#define TIME_WITE_REQUEST 60000 //в минутах 1 мин


DWORD ReportFailure()
{
	DWORD err;
	switch (err = GetLastError())
	{
	case CRYPT_E_AUTH_ATTR_MISSING:
		printf("Message does not contain an expected "
			"attribute.\n");
		break;
	case CRYPT_E_BAD_ENCODE:
		printf("An error encountered encoding or decoding.\n");
		break;
	case CRYPT_E_HASH_VALUE:
		printf("The hash value is not correct.\n");
		break;
	case CRYPT_E_INVALID_MSG_TYPE:
		printf("The message type is not valid.\n");
		break;
	case CRYPT_E_OSS_ERROR:
		printf("OSS error.\n");
		break;
	case CRYPT_E_SIGNER_NOT_FOUND:
		printf("Signer not found.\n");
		break;
	case CRYPT_E_UNEXPECTED_ENCODING:
		printf("Unexpected encoding. \n");
		break;
	case CRYPT_E_UNKNOWN_ALGO:
		printf("Unknown algorithm.\n");
		break;
	case E_OUTOFMEMORY:
		printf("Out of memory.\n");
		break;
	case ERROR_INVALID_HANDLE:
		printf("The handle from verify signature is not valid function.\n");
		break;
	case ERROR_INVALID_PARAMETER:
		printf("The parameter from verify signature "
			"is not valid.\n");
		break;
	case NTE_BAD_FLAGS:
		printf("Bad Flags from verify signature function.\n");
		break;
	case NTE_BAD_HASH:
		printf("Bad Hash from verify signature function.\n");
		break;
	case NTE_BAD_KEY:
		printf("Bad Key from verify signature function.\n");
		break;
	case NTE_BAD_SIGNATURE:
		printf("Bad signature from verify signature " \
			"function.\n");
		break;
	case NTE_BAD_UID:
		printf("Bad UID from verify signature function.\n");
		break;
	}
	return err;
}

void HandleError(char *s)
{
	DWORD err = ReportFailure();
	printf("Error number     : 0x%x\n", err);
	printf("Error description: %s\n", s);
	if(!err) err = 1;
	exit(err);
}

// переделать под stream
static std::string readInputTestFile( const char *path )
{
   FILE *file;
   fopen_s(&file, path, "rb" );
   if ( !file )
      return std::string("");
   fseek( file, 0, SEEK_END );
   long size = ftell( file );
   fseek( file, 0, SEEK_SET );
   std::string text;
   char *buffer = new char[size+1];
   buffer[size] = 0;
   if ( fread( buffer, 1, size, file ) == (unsigned long)size )
      text = buffer;
   fclose( file );
   delete[] buffer;
   return text;
}


int main(int argc, char* argv[])
{
	// Определяем хранилище и структуру для сертификата
	HCERTSTORE hCertStore = NULL;        
	PCCERT_CONTEXT  pCert = NULL; 

	// Открываем хранилище сертификатов
	if (!(hCertStore = CertOpenSystemStore(NULL, "MY")))
	{
		HandleError("The store was not opened.");
	}
	// Выбираем сертификат
	if(!(pCert = CryptUIDlgSelectCertificateFromStore( hCertStore, NULL, NULL, NULL, CRYPTUI_SELECT_LOCATION_COLUMN, 0, NULL)))
	{
		HandleError("Select UI failed." );
	}
	// Создаем, "зерошим" и инициируем поля структуры для создания отсоедененной подписи PKCS7
	CRYPT_SIGN_MESSAGE_PARA SignPara;
	ZeroMemory(&SignPara, sizeof(SignPara));
	SignPara.cbSize = sizeof(SignPara);
	SignPara.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
	SignPara.HashAlgorithm.pszObjId = (LPSTR)CertAlgIdToOID(CALG_SHA1);
	SignPara.pSigningCert = pCert;
	SignPara.cMsgCert = 1;
	SignPara.rgpMsgCert = &pCert;
	
	// Следующие структуры нам нужны для выполнения запросов gSOAP
	struct soap soap;

	_ns1__getLastDumpDate getLastDumpDate;
	_ns1__getLastDumpDateResponse getLastDumpDateResponse;

	_ns1__sendRequest sendRequest;
	_ns1__sendRequestResponse sendRequestResponse;

	_ns1__getResult getResult;
	_ns1__getResultResponse getResultResponse;

	// Вообщето все работает и так, но положено инициировать на всякий случай
	soap_init(&soap); 
	soap_set_namespaces(&soap, namespaces); 

	// Сам XML запрос
	string request;

	Json::Value root;   // will contains the root value after parsing.
	Json::Reader reader;

	string input = readInputTestFile( "config.json" );
	if ( input.empty() )
	{
		cout<< "Failed to read input or empty input"<<endl;
		return 3;
	}
   
	bool parsingSuccessful = reader.parse( input, root );
	if ( !parsingSuccessful )
	{
		// report to the user the failure and their locations in the document.
		cout  << "Failed to parse configuration\n" << reader.getFormatedErrorMessages();
	}
	
	time_t last_time = time(0); 

	for(;;)
	{
		char buff[64]; // размер явно завышен, но пусть будет
		
		if(0!=soap_call___ns1__getLastDumpDate(&soap,NULL,NULL,&getLastDumpDate, &getLastDumpDateResponse))
		{
			 soap_print_fault(&soap, stderr); 
		} else {
			const time_t* last_update_time = &getLastDumpDateResponse.lastDumpDate;
			if(last_time!=*last_update_time)
			{
				tm ltm;
				time_t now = time(0);
				localtime_s(&ltm,&now);
				last_time = *last_update_time;
				strftime(buff,sizeof(buff),"%H:%M:%S  %d/%m/%y",&ltm);
				cout << "New black reestr will be downloaded : " << buff << endl;

				request.clear();
				request += "<?xml version=\"1.0\" encoding=\"windows-1251\"?>\n";
				request += "<request>\n";
				request += "<requestTime>";
				now = time(0);
				localtime_s(&ltm,&now);
				strftime(buff,sizeof(buff),"%Y-%m-%dT%H:%M:%S.000+04:00",&ltm);
				request += buff;
				request += "</requestTime>\n";
				request += "<operatorName>";
				request += "<![CDATA[" + root["operatorName"].asString() + "]]>";
				request += "</operatorName>\n";
				request += "<inn>";
				request += root["inn"].asString();
				request += "</inn>\n";
				request += "<ogrn>";
				request += root["ogrn"].asString();
				request += "</ogrn>\n";
				request += "<email>";
				request += root["email"].asString();
				request += "</email>\n";
				request += "</request>";
				
				#ifdef _DEBUG
				ofstream myfile;
				myfile.open("request.xml",ios::out);
				myfile.write(request.data(),request.size());
				myfile.close();
				#endif

				const BYTE* DataArray[] = { (BYTE*)request.data() };
				DWORD SizeArray[] = { strlen(request.data()) };
				DWORD count = 0;
				// Определяем примерный размер будующей подписи
				if(!CryptSignMessage(&SignPara,TRUE,1,DataArray,SizeArray,NULL,&count))
				{
					HandleError("Signature unsuccessful phase 1");
				}
				// Выделяем под нее память
				BYTE* signature = static_cast<BYTE*>(malloc(count));
				// И подписываем
				if(!CryptSignMessage(&SignPara,TRUE,1,DataArray,SizeArray,signature,&count))
				{
					HandleError("Signature unsuccessful phase 2");
				}

				sendRequest.requestFile.__ptr = (unsigned char*)request.data();
				sendRequest.requestFile.__size = request.size();
				sendRequest.signatureFile.__ptr = signature;
				sendRequest.signatureFile.__size = count;

				if(0!=soap_call___ns1__sendRequest(&soap,NULL,NULL,&sendRequest,&sendRequestResponse))
				{
					soap_print_fault(&soap, stderr); 
				} else {
					getResult.code = sendRequestResponse.code;
					do {
						Sleep(TIME_WITE_REQUEST);
						soap_call___ns1__getResult(&soap,NULL,NULL,&getResult,&getResultResponse);
						// Разобраться в какой кодировке возвращает коммент
						/*try{
							if(NULL!=getResultResponse.resultComment) cout << getResultResponse.resultComment << endl;
						} catch(exception& e) {
							cerr << e.what();
						}*/
					} while(!getResultResponse.result);
					// Подпись пока не проверяем
					time_t now = time(0);
					localtime_s(&ltm,&now);
					strftime(buff,sizeof(buff),"reestr%d_%m_%H-%M-%S.zip",&ltm);
					ofstream myfile;
					myfile.open(buff,ios::out | ios::binary);
					myfile.write((const char*)getResultResponse.registerZipArchive->__ptr,getResultResponse.registerZipArchive->__size);
					myfile.close();
					cout << "Black reestr was written as file: "<< buff << endl;
				}
				free(signature);
			}
		}

		Sleep(TIME_UPDATE);
	}

	return 0;
}
