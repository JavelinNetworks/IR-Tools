#include "StdAfx.h"
#include "assert.h"
#include "string_parser.h"
#include "strings2.h"
#include "Strings2ManagedWrapper.h"
#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>

using namespace System;
using namespace msclr::interop;
using namespace System::Collections;


int string_parser::extractImmediate( char* immediate, int immediateSize, STRING_TYPE &stringType, unsigned char* outputString )
{
	// Extract unicode or ascii from the immediate constant.
	// Assumes: outputString + 4 is a valid address.
	int i = 0;
	switch(stringType)
	{
		case TYPE_ASCII:
			// Parse the immediate as ascii
			while( i < immediateSize && isAscii[immediate[i]] )
			{
				*outputString = immediate[i];
				outputString++;
				i++;
			}
			return i;

		case TYPE_UNICODE:
			// Parse the immediate as unicode
			while( i+1 < immediateSize && isAscii[immediate[i]] && immediate[i+1] == 0 )
			{
				*outputString = immediate[i];
				outputString++;
				i+=2;
			}
			return i/2;

		case TYPE_UNDETERMINED:
			// Determine if this is ascii or unicode
			if( !isAscii[immediate[0]] )
			{
				// Not unicode or ascii, return.
				return 0;
			}else if( immediateSize > 1 && immediate[1] == 0 )
			{
				// Recurse as Unicode
				stringType = TYPE_UNICODE;
				return extractImmediate( immediate, immediateSize, stringType, outputString );
			}else{
				// Recurse as Ascii
				stringType = TYPE_ASCII;
				return extractImmediate( immediate, immediateSize, stringType, outputString );
			}
	
		default:
			break;
	}
	return 0;
}

int string_parser::extractString( unsigned char* buffer, long bufferSize, long offset, unsigned char* outputString, int outputStringSize, int &outputStringLength, EXTRACT_TYPE & extractType, STRING_TYPE & stringType)
{
	// Process the string as either:
	// 1. ascii
	// 2. unicode
	// 3. x86 ASM stack pushes
	// TODO: 4. x64 ASM stack pushes
	//
	// To improve performance:
	//	Assumes MAX_STRING_SIZE > 1
	//	Assumes MinStringSize > 1
	//  Assumes offset + 3 < bufferSize
	// These assumptions must be validated by the calling function.
	
	// Supported string push formats
	// C6 45     mov byte [ebp+imm8], imm8
	// C6 85     mov byte [ebp+imm32], imm8
	// 66 C7 45  mov word [ebp+imm8], imm16
	// 66 C7 85  mov word [ebp+imm32], imm16
	// C7 45     mov dword [ebp+imm8], imm32
	// C7 85     mov dword [ebp+imm32], imm32

	// Set unknown string type
	extractType = EXTRACT_RAW;
	outputStringLength = 0;
	int i = 0;
	int instSize;
	int immSize;
	int immOffset;
	int maxStringSize;
	int size;


	unsigned _int16 value = *((unsigned _int16*) (buffer+offset));
	// Switch on the first two bytes
	switch( value )
	{
		case 0x45C6:
			//  0  1  0  [0]
			// C6 45     mov byte [ebp+imm8], imm8
			instSize = 4;
			immSize = 1;
			immOffset = instSize - immSize;
			maxStringSize = 1;
			while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
					&& buffer[offset+i] == 0xC6 && buffer[offset+i+1] == 0x45 )
			{
				
				// Process this immediate
				size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
				outputString += size;
				outputStringLength += size;
				
				i+=instSize;

				if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
					|| (stringType == TYPE_ASCII && size < immSize ) )
					break;
			}
			extractType = EXTRACT_ASM;
			return i;

		case 0x85C6:
			//  0  1  0  1  2  3  4  [0]
			// C6 85     mov byte [ebp+imm32], imm8
			instSize = 8;
			immSize = 1;
			immOffset = instSize - immSize;
			maxStringSize = 1;
			while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
					&& buffer[offset+i] == 0xC6 && buffer[offset+i+1] == 0x85 )
			{
				
				// Process this immediate
				size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
				outputString += size;
				outputStringLength += size;
				
				i+=instSize;

				if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
					|| (stringType == TYPE_ASCII && size < immSize ) )
					break;
			}
			extractType = EXTRACT_ASM;
			return i;

		case 0x45C7:
			// 0  1  0  [0  1  2  3]
			// C7 45     mov dword [ebp+imm8], imm32
			instSize = 7;
			immSize = 4;
			immOffset = instSize - immSize;
			maxStringSize = 4;
			while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
					&& buffer[offset+i] == 0xC7 && buffer[offset+i+1] == 0x45 )
			{
				
				// Process this immediate
				size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
				outputString += size;
				outputStringLength += size;
				
				i+=instSize;

				if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
					|| (stringType == TYPE_ASCII && size < immSize ) )
					break;
			}
			extractType = EXTRACT_ASM;
			return i;

		case 0x85C7:
			// 0  1  0  1  2  3  [0  1  2  3]
			// C7 85     mov dword [ebp+imm32], imm32
			instSize = 10;
			immSize = 4;
			immOffset = instSize - immSize;
			maxStringSize = 4;
			while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
					&& buffer[offset+i] == 0xC7 && buffer[offset+i+1] == 0x85 )
			{
				
				// Process this immediate
				size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
				outputString += size;
				outputStringLength += size;
				
				i+=instSize;

				if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
					|| (stringType == TYPE_ASCII && size < immSize ) )
					break;
			}
			extractType = EXTRACT_ASM;
			return i;

		case 0xC766:
			if( buffer[offset+2] == 0x45 )
			{
				// 0  1  2  0  [0  1]
				// 66 C7 45  mov word [ebp+imm8], imm16
				instSize = 6;
				immSize = 2;
				immOffset = instSize - immSize;
				maxStringSize = 2;
				while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
						&& buffer[offset+i] == 0x66 && buffer[offset+i+1] == 0xC7 && buffer[offset+i+2] == 0x45 )
				{
					
					// Process this immediate
					size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
					outputString += size;
					outputStringLength += size;
					
					i+=instSize;

					if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
						|| (stringType == TYPE_ASCII && size < immSize ) )
						break;
				}
				extractType = EXTRACT_ASM;
				return i;
			}else if( buffer[offset+2] == 0x85 )
			{
				// 0  1  2  0  1  2  3  [0  1]
				// 66 C7 85  mov word [ebp+imm32], imm16
				i = 0;
				instSize = 9;
				immSize = 2;
				immOffset = instSize - immSize;
				maxStringSize = 2;
				while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
						&& buffer[offset+i] == 0x66 && buffer[offset+i+1] == 0xC7 && buffer[offset+i+2] == 0x85 )
				{
					
					// Process this immediate
					size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
					outputString += size;
					outputStringLength += size;
					
					i+=instSize;

					if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
						|| (stringType == TYPE_ASCII && size < immSize ) )
						break;
				}
				extractType = EXTRACT_ASM;
				return i;
			}
			break;

		default:
			// Try to parse as ascii or unicode
			if( isAscii[buffer[offset]] )
			{
				// Consider unicode case
				if( buffer[offset+1] == 0 ) // No null dereference by assumptions
				{
					// Parse as unicode
					while( offset+i+1 < bufferSize && i/2 < outputStringSize && isAscii[buffer[offset+i]] && buffer[offset+i+1] == 0 && i/2 + 1 < outputStringSize )
					{
						// Copy this character
						outputString[i/2] = buffer[offset+i];
						
						i+=2;
					}
					outputStringLength = i / 2;
					stringType = TYPE_UNICODE;
					return i;
				}else
				{
					// Parse as ascii
					i = offset;
					while( i < bufferSize && isAscii[buffer[i]] )
						i++;
					outputStringLength = i - offset;
					if( outputStringLength > outputStringSize )
						outputStringLength = outputStringSize;

					// Copy this string to the output
					memcpy( outputString, buffer + offset, outputStringLength );
					stringType = TYPE_ASCII;
					return outputStringLength;
				}
			}
	}

	outputStringLength = 0;
	return 0;
}


bool string_parser::processContents(unsigned char* filecontents, long bufferSize, LPCSTR filename, List<String^>^ lst)
{

	// Process the contents of the specified file, and build the list of strings
	unsigned char* outputString = new unsigned char[MAX_STRING_SIZE+1];
	int totalsize = 100000;
	int outputStringSize = 0;

	long offset = 0;
	EXTRACT_TYPE extractType;
	while( offset + options.minCharacters < bufferSize )
	{
		// Process this offset
		STRING_TYPE stringType = TYPE_UNDETERMINED;
		int stringDiskSpace = extractString( filecontents, bufferSize, offset, outputString, MAX_STRING_SIZE, outputStringSize, extractType, stringType );

		if( outputStringSize >= options.minCharacters )
		{
			// Print the resulting string
			outputString[outputStringSize] = 0;

			
			// Decide if we should print this
			bool print = true;
			if( options.printNormal && extractType == EXTRACT_RAW )
				print = true;
			else if( options.printASM && extractType == EXTRACT_ASM )
				print = true;

			if( options.printUnicodeOnly && stringType != TYPE_UNICODE )
				print = true;
			if( options.printAsciiOnly && stringType != TYPE_ASCII )
				print = true;

			if( print )
			{
				// Replace \n with "\\n" and \r with "\\r"
				if( options.escapeNewLines )
				{
					int i = 0;
					while( i < outputStringSize && outputStringSize + 2 < MAX_STRING_SIZE )
					{
						if( outputString[i] == '\n' )
						{
							memmove(outputString+i+2, outputString+i+1, (outputStringSize) - i);
							outputString[i] = '\\';
							outputString[i+1] = 'n';
							outputStringSize++;
						}else if( outputString[i] == '\r' )
						{
							memmove(outputString+i+2, outputString+i+1, (outputStringSize) - i);
							outputString[i] = '\\';
							outputString[i+1] = 'r';
							outputStringSize++;
						}
						i++;
					}
				}

				if( (!options.printUniqueLocal && !options.printUniqueGlobal))
				{
					WCHAR s[MAX_LENGTH + MAX_STRING_SIZE] = {0};

					if( options.printType && options.printFile )
						swprintf(s, L"%S %S %S %S", (char*)filename, ",", (extractType == EXTRACT_RAW ? (stringType == TYPE_UNICODE ? "UNICODE: " : (stringType == TYPE_ASCII ? "ASCII: " : "UNDETERMINED: ")) : "ASM: "), (char*)outputString);
					else if( options.printType )
						swprintf(s, L"%S %S", (extractType == EXTRACT_RAW ? (stringType == TYPE_UNICODE ? "UNICODE: " : (stringType == TYPE_ASCII ? "ASCII: " : "UNDETERMINED: ")) : "ASM: "), (char*)outputString);
					else if( options.printFile )
						swprintf(s, L"%S %S %S", (char*)filename, ": ", (char*)outputString);
					else
						swprintf(s, L"%S", (char*)outputString);

					marshal_context^ context = gcnew marshal_context();
					String^ ms = context->marshal_as<String^>(s);
					lst->Add(ms);
					delete context;

				}
				
			}

			// Advance the offset
			offset += stringDiskSpace;
		}else{
			// Advance the offset by 1
			offset += 1;
		}
	}

	delete[] outputString;
	return true;
}


bool string_parser::parse_block(unsigned char* buffer, unsigned int buffer_length, LPCSTR datasource, List<String^>^ lst)
{
	if( buffer != NULL && buffer_length > 0)
	{
		// Process this buffer
		return this->processContents(buffer, buffer_length, datasource, lst);
	}
	return false;
}

string_parser::string_parser(STRING_OPTIONS options)
{
	printer = new print_buffer(0x100000);
	this->options = options;
}

bool string_parser::parse_stream(FILE* fh, LPCSTR datasource, List<String^>^ lst)
{

	if( fh != NULL )
	{
		
		unsigned char* buffer;
		int numRead;

		// Allocate the buffer

		do
		{
			buffer = new unsigned char[BLOCK_SIZE];

			// Read the stream in blocks of 0x50000, assuming that a string does not border the regions.
			numRead = fread( buffer, 1, BLOCK_SIZE - 1, fh);
			buffer[numRead] = 0;

			if( numRead > 0 )
			{
				// We have read in the full contents now, lets process it.
				this->processContents(buffer, numRead, datasource, lst);

			}
		} while (!feof(fh));

		// Clean up
		delete[] buffer;
		return true;
	}else{
		// Failed to open file
		fprintf(stderr,"Invalid stream: %s.\n", strerror(errno));
		return false;
	}
}

string_parser::~string_parser(void)
{
	delete printer;
}
