// ADEvents.h

#pragma once

#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <xstring>
#include <conio.h>
#include <EvColl.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <msclr\marshal_cppstd.h>

#pragma comment(lib, "credui.lib")
#pragma comment(lib, "wecapi.lib")

using namespace std;
using namespace System;
using namespace System::Collections::Generic;
using namespace System::Diagnostics;
using namespace System::Text;
using namespace System::IO;
using namespace System::Text::RegularExpressions;

namespace Strings2Managed {

	public ref class Strings2ManagedWrapper
	{
	public:
		List<String^>^ FileToStrings(String^ path);
		List<String^>^ ProcessToStrings(int processID);
	};
}
