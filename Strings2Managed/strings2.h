#include "windows.h"

#include <msclr\marshal_cppstd.h>

using namespace std;
using namespace System;
using namespace System::Collections::Generic;
using namespace System::Diagnostics;
using namespace System::Text;
using namespace System::IO;
using namespace System::Text::RegularExpressions;

const int MAX_LENGTH = 10000;
const int INFO_ARGS = 3;

void mainFunction(WCHAR** infoArgs, int numInfoArgs, List<String^>^ lst);