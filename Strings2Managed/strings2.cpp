// Modified By Javelin Networks.
// strings.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "string_parser.h"
#include "windows.h"
#include <sys/types.h>
#include "dirent.h"
#include <errno.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include "process_strings.h"
#include "strings2.h"

using namespace System;
using namespace msclr::interop;
using namespace System::Collections;

using namespace std;


BOOL Is64BitWindows()
{
#if defined(_WIN64)
	return TRUE;  // 64-bit programs run only on Win64
#elif defined(_WIN32)
	// 32-bit programs run on both 32-bit and 64-bit Windows
	// so must sniff
	BOOL f64 = FALSE;
	return IsWow64Process(GetCurrentProcess(), &f64) && f64;
#else
	return FALSE; // Win64 does not support Win16
#endif
}

bool isElevated(HANDLE h_Process)
{
	HANDLE h_Token;
	TOKEN_ELEVATION t_TokenElevation;
	TOKEN_ELEVATION_TYPE e_ElevationType;
	DWORD dw_TokenLength;

	if (OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token))
	{
		if (GetTokenInformation(h_Token, TokenElevation, &t_TokenElevation, sizeof(t_TokenElevation), &dw_TokenLength))
		{
			if (t_TokenElevation.TokenIsElevated != 0)
			{
				if (GetTokenInformation(h_Token, TokenElevationType, &e_ElevationType, sizeof(e_ElevationType), &dw_TokenLength))
				{
					if (e_ElevationType == TokenElevationTypeFull || e_ElevationType == TokenElevationTypeDefault)
					{
						return true;
					}
				}
			}
		}
	}

	return false;
}


bool getMaximumPrivileges(HANDLE h_Process)
{
	HANDLE h_Token;
	DWORD dw_TokenLength;
	if (OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token))
	{
		// Read the old token privileges
		TOKEN_PRIVILEGES* privilages = new TOKEN_PRIVILEGES[100];
		if (GetTokenInformation(h_Token, TokenPrivileges, privilages, sizeof(TOKEN_PRIVILEGES) * 100, &dw_TokenLength))
		{
			// Enable all privileges
			for (int i = 0; i < privilages->PrivilegeCount; i++)
			{
				privilages->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
			}

			// Adjust the privilges
			if (AdjustTokenPrivileges(h_Token, false, privilages, sizeof(TOKEN_PRIVILEGES) * 100, NULL, NULL))
			{
				delete[] privilages;
				return true;
			}
		}
		delete[] privilages;
	}
	return false;
}

void mainFunction(WCHAR** infoArgs, int numInfoArgs, List<String^>^ lst)
{
	//	 Process the flags	
	WCHAR* filter = NULL;
	WCHAR* filePath = NULL;
	bool flagHelp = false;
	bool flagHeader = false;
	bool flagFile = false;
	bool flagFilePath = false;
	bool flagPrintType = false;
	bool flagAsmOnly = false;
	bool flagRawOnly = false;
	bool flagAsciiOnly = false;
	bool flagUnicodeOnly = true;
	bool pipedInput = !_isatty(_fileno(stdin));
	bool flagPidDump = false;
	bool flagSystemDump = false;
	bool flagRecursive = false;
	bool flagEscape = false;
	int minCharacters = 4;

	if (numInfoArgs <= 1 && !pipedInput)
		flagHelp = true;

	for (int i = 1; i < numInfoArgs; i++)
	{
		if (lstrcmp(infoArgs[i], L"-f") == 0)
			flagFile = true;
		else if (lstrcmp(infoArgs[i], L"-file") == 0)
		{
			flagFilePath = true;

			if (i + 1 < numInfoArgs)
			{
				// get the file path.
				filePath = infoArgs[i + 1];
				i++;
			}
		}
		else if (lstrcmp(infoArgs[i], L"-t") == 0)
			flagPrintType = true;
		else if (lstrcmp(infoArgs[i], L"-r") == 0)
			flagRecursive = true;
		else if (lstrcmp(infoArgs[i], L"-h") == 0)
			flagHeader = true;
		else if (lstrcmp(infoArgs[i], L"-asm") == 0)
			flagAsmOnly = true;
		else if (lstrcmp(infoArgs[i], L"-raw") == 0)
			flagRawOnly = true;
		else if (lstrcmp(infoArgs[i], L"-pid") == 0)
			flagPidDump = true;
		else if (lstrcmp(infoArgs[i], L"-system") == 0)
			flagSystemDump = true;
		else if (lstrcmp(infoArgs[i], L"-a") == 0)
			flagAsciiOnly = true;
		else if (lstrcmp(infoArgs[i], L"-u") == 0)
			flagUnicodeOnly = true;
		else if (lstrcmp(infoArgs[i], L"-e") == 0)
			flagEscape = true;
		else if (lstrcmp(infoArgs[i], L"-l") == 0)
		{
			if (i + 1 < numInfoArgs)
			{
				// Try to parse the number of characters
				int result = _wtoi(infoArgs[i + 1]);
				if (result >= 3)
				{
					minCharacters = result;
				}
				else{
					fprintf(stderr, "Failed to parse -l argument. The string size must be 3 or larger:\n\teg. 'strings2 *.exe -l 6'\n");
					exit(0);
				}
				i++;
			}
			else{
				fprintf(stderr, "Failed to parse -l argument. It must be preceeded by a number:\n\teg. 'strings2 *.exe -l 6'\n");
				exit(0);
			}
		}
		else{
			// This is an unassigned argument
			if (filter == NULL)
			{
				filter = infoArgs[i];
			}
			else
			{
				// This argument is an error, we already found our filter.
				fprintf(stderr, "Failed to parse argument number %i, '%S'. Try 'strings2 --help' for usage instructions.\n", i, infoArgs[i]);
				exit(0);
			}
		}
	}

	// Fill out the options structure based on the flags
	STRING_OPTIONS options;
	options.printUniqueGlobal = false;
	options.printUniqueLocal = false;

	options.printAsciiOnly = false;
	options.printUnicodeOnly = false;
	options.printNormal = false;
	options.printASM = false;
	options.escapeNewLines = flagEscape;
	if (flagAsmOnly)
		options.printASM = true;
	if (flagRawOnly)
		options.printNormal = true;
	if (!flagAsmOnly && !flagRawOnly)
	{
		options.printASM = true;
		options.printNormal = true;
	}

	if (flagAsciiOnly && flagUnicodeOnly)
	{
		fprintf(stderr, "Warning. Default conditions extract both unicode and ascii strings. There is no need to use both '-a' and '-u' flags at the same time.\n");
	}
	else{
		if (flagAsciiOnly)
			options.printAsciiOnly = true;
		if (flagUnicodeOnly)
			options.printUnicodeOnly = true;
	}


	options.printType = flagPrintType;
	options.printFile = flagFile;
	options.minCharacters = minCharacters;

	// Print copyright header
	if (flagHeader)
	{
		printf("Modified Strings2 v1.3\n");
		printf("  Copyright © 2016, Geoff McDonald\n");
		printf("  Modified by Adam Cheriki and Eyal Neemany, 2017\n");
		printf("  http://www.split-code.com/\n\n");
		printf("  http://www.Javelin-Networks.com\n");
	}


	// Create the string parser object
	string_parser* parser = new string_parser(options);

	if (flagPidDump || flagSystemDump)
	{
		// Warn if running in 32 bit mode on a 64 bit OS
		if (Is64BitWindows() && sizeof(void*) == 4)
		{
			fprintf(stderr, "WARNING: To properly dump address spaces of 64-bit processes the 64-bit version of strings2 should be used. Currently strings2 has been detected as running as a 32bit process under a 64bit operating system.\n\n");
		}

		// Elevate strings2 to the maximum privilges
		getMaximumPrivileges(GetCurrentProcess());

		// Create a process string dump class
		process_strings* process = new process_strings(parser);

		if (flagPidDump)
		{
			//process->dump_process(4932);
			// Extract all strings from the specified process
			if (filter != NULL)
			{
				// Check the prefix
				bool isHex = false;
				wchar_t* prefix = new wchar_t[3];
				memcpy(prefix, filter, 4);
				prefix[2] = 0;

				if (wcscmp(prefix, L"0x") == 0)
				{
					filter = &filter[2];
					isHex = true;
				}
				delete[] prefix;

				// Extract the pid from the string
				unsigned int PID;
				if ((isHex && swscanf(filter, L"%x", &PID) > 0) ||
					(!isHex && swscanf(filter, L"%i", &PID) > 0))
				{
					// Successfully parsed the PID

					// Parse the process
					process->dump_process(PID, lst);


				}
				else{
					fwprintf(stderr, L"Failed to parse filter argument as a valid PID: %s.\n", filter);
				}
			}
			else{
				fwprintf(stderr, L"Error. No PID was specified. Example usage:\n\tstrings2 -pid 419 > process_strings.txt\n", filter);
			}
		}
		else if (flagSystemDump)
		{
			// Extract strings from the whole system
			process->dump_system(lst);
		}

		delete process;
	}
	else if (pipedInput)
	{
		// Set "stdin" to have binary mode:
		int result = _setmode(_fileno(stdin), _O_BINARY);
		if (result == -1)
			fprintf(stderr, "Failed to set piped data mode to binary but will continue with processing of piped data.");

		FILE* fh = fdopen(fileno(stdin), "rb");

		if (fh != NULL)
		{
			// Process the piped input
			parser->parse_stream(fh, "piped data", lst);
			fclose(fh);
		}
		else{
			// Error
			fprintf(stderr, "Invalid stream: %s.\n", "Error opening the piped input: %s.\n", strerror(errno));
		}
	}
	else if (filter != NULL)
	{
		// Split the filter into the directory and filename filter halves
		char path[MAX_PATH + 1] = { '.', 0 };
		wchar_t* last_slash = wcsrchr(filter, '\\');
		if (last_slash == NULL || wcsrchr(filter, '/') > last_slash)
			last_slash = wcsrchr(filter, '/');

		if (last_slash != NULL)
		{
			// Copy the path
			sprintf_s(path, MAX_PATH + 1, "%S", filter);
			path[last_slash - filter] = 0;

			// Move the filter
			memmove(filter, last_slash + 1, (wcslen(last_slash + 1) + 1) * 2);
		}

	}
	else if (flagFilePath)
	{
		char* errorMessage = "\"%ls\" is not a valid PATH\n";

		try{
			char fPath[5000];
			*fPath = 0;
			sprintf_s(fPath, "%ls", filePath);
			FILE* file;
			long error = fopen_s(&file, fPath, "rb");
			if (error == 0){
				parser->parse_stream(file, fPath, lst);
				fclose(file);
			}
			else
			{
				printf(errorMessage, filePath);
			}
		}
		catch (int)
		{
			printf(errorMessage, filePath);
		}
	}

	// Cleanup the string parser
	delete parser;
}

