// This is the main DLL file.

#include <msclr\marshal_windows.h>,
#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>
#include <stdlib.h>
#include <string.h>
#include <msclr\marshal.h>
#include "stdafx.h"
#include "strings2.h"
#include "Strings2ManagedWrapper.h"
using namespace System;
using namespace msclr::interop;
using namespace System::Collections;



namespace Strings2Managed {

	List<String^>^ Strings2ManagedWrapper::FileToStrings(String^ filePath)
	{
		wstring x = msclr::interop::marshal_as<std::wstring>(filePath);
		WCHAR path[MAX_LENGTH] = { 0 };
		swprintf_s(path, L"%ls", x.c_str());
		WCHAR** infoArgs = (WCHAR**)malloc(INFO_ARGS * sizeof(WCHAR*));
		infoArgs[0] = L"";
		infoArgs[1] = L"-file";
		infoArgs[2] = path;
		List<String^>^ res = gcnew List<String^>();

		mainFunction(infoArgs, INFO_ARGS, res);

		return res;
	}

	List<String^>^ Strings2ManagedWrapper::ProcessToStrings(int processID)
	{
		WCHAR path[MAX_LENGTH] = { 0 };
		swprintf_s(path, L"%d", processID);
		WCHAR** infoArgs = (WCHAR**)malloc(INFO_ARGS * sizeof(WCHAR*));
		infoArgs[0] = L"";
		infoArgs[1] = L"-pid";
		infoArgs[2] = path;
		List<String^>^ res = gcnew List<String^>();

		mainFunction(infoArgs, INFO_ARGS, res);

		return res;
	}
}