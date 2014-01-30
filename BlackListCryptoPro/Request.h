#pragma once

#include <iostream>
#include <string>
#include <ctime>

using namespace std;

class Request
{
public:
	string request, signature;
	Request(string operatorName, string inn, string ogrn, string email);
	~Request(void);
};
