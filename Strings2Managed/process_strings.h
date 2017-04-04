#pragma once
#include "windows.h"
#include "module.h"
#include <tlhelp32.h>
#include "string_parser.h"
#include <Psapi.h>
#include "basics.h"
#pragma comment(lib, "Psapi")
#include <msclr\marshal_cppstd.h>

using namespace std;
using namespace System;
using namespace System::Collections::Generic;
using namespace System::Diagnostics;
using namespace System::Text;
using namespace System::IO;
using namespace System::Text::RegularExpressions;


class process_strings
{
	DynArray<module*> modules;
	string_parser* parser;

	void generateModuleList(HANDLE hSnapshot);
	bool processAllHeaps(HANDLE ph, char* process_name, List<String^>^ lst);
public:
	process_strings(string_parser* parser);
	bool dump_process(DWORD pid, List<String^>^ lst);
	bool dump_system(List<String^>^ lst);
	~process_strings(void);
};
