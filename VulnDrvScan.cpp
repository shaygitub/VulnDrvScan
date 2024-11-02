#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <Windows.h>
#include <winternl.h>

// Definitions:
const char* search_imports[9] = {
	"MmMapIoSpace",
	"MmMapIoSpaceEx",
	"MmMapLockedPages",
	"MmMapLockedPagesSpecifyCache",
	"MmMapLockedPagesWithReservedMapping",
	"IoAllocateMdl",
	"ZwMapViewOfSection",
	"MmCopyVirtualMemory",
	"IoCreateSymbolicLink"
};
const char* NotVulnerableList[] = {
	"spaceparser.sys",
	"vmkbd.sys",
	"spaceport.sys"
};
const char* source_module = "ntoskrnl.exe";  // system services hosted in the kernel executable
HANDLE VulnRes = NULL;  // file handle for vulnurable drivers results


void WriteResultsFile(const char* DriverName, const char* DriverFunc, BOOL IsFirst) {
	PVOID WriteName = NULL;
	PVOID WriteFunc = NULL;
	const char* AddToName = "-\n  ";
	const char* AddToFunc = "\n  ";
	const char* AddBeforeName = "\n";

	if (IsFirst) {
		WriteName = malloc(strlen(DriverName) + strlen(AddToName) + strlen(AddBeforeName));
		memcpy(WriteName, AddBeforeName, strlen(AddBeforeName));
		memcpy((PVOID)((ULONG64)WriteName + strlen(AddBeforeName)), DriverName, strlen(DriverName));
		memcpy((PVOID)((ULONG64)WriteName + strlen(AddBeforeName) + strlen(DriverName)), AddToName, strlen(AddToName));

		WriteFile(
			VulnRes,
			WriteName,
			strlen(DriverName) + strlen(AddToName) + strlen(AddBeforeName),
			NULL,
			NULL);
		free(WriteName);
	}
	
	WriteFunc = malloc(strlen(DriverFunc) + strlen(AddToFunc));
	memcpy(WriteFunc, DriverFunc, strlen(DriverFunc));
	memcpy((PVOID)((ULONG64)WriteFunc + strlen(DriverFunc)), AddToFunc, strlen(AddToFunc));
	WriteFile(
		VulnRes,
		WriteFunc,
		strlen(DriverFunc) + strlen(AddToFunc),
		NULL,
		NULL);
	free(WriteFunc);
}


PIMAGE_NT_HEADERS GetNtHeader(PVOID DriverDataBase, BOOL Silent) {
	if (!Silent) {
		printf("[INF] GetNtHeader, getting NT header of driver with driver data base address of %p ..\n", DriverDataBase);
	}

	PIMAGE_DOS_HEADER DosHeader = PIMAGE_DOS_HEADER((ULONG64*)DriverDataBase);  // Get dos header for e_lfanew
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		if (!Silent) {
			printf("[ERR] GetNtHeader, dos signature is %u instead of %u\n", DosHeader->e_magic, IMAGE_DOS_SIGNATURE);
		}
		return NULL;
	}

	PIMAGE_NT_HEADERS NtHeader = PIMAGE_NT_HEADERS((ULONG*)((ULONG64)DriverDataBase + (ULONG64)DosHeader->e_lfanew));  // Get NT header with rva of nt header + actual address of driver data in memory
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE || NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		if (!Silent) {
			printf("[ERR] GetNtHeader, NT signature is %u instead of %u / NT.FileHeader.Machine is %u instead of %u\n", NtHeader->Signature, (WORD)IMAGE_NT_SIGNATURE, NtHeader->FileHeader.Machine, (WORD)IMAGE_FILE_MACHINE_AMD64);
		}
		return NULL;
	}
	if (!Silent) {
		printf("[SUC] GetNtHeader, success in getting the NT header of the driver file ..\n");
	}
	return NtHeader;
}


ULONG64 RvaToActualVa(PVOID DriverDataBase, DWORD RelativeVa, BOOL Silent) {
	if (!Silent) {
		printf("[INF] RvaToActualVa, converting RVA %lu with driver data base address of %p ..\n", RelativeVa, DriverDataBase);
	}

	ULONG64 VaOfRva = NULL;
	PIMAGE_NT_HEADERS NtHeader = GetNtHeader((ULONG64*)DriverDataBase, TRUE);  // Get NT header of driver
	PIMAGE_SECTION_HEADER SectionsOfFile = IMAGE_FIRST_SECTION(NtHeader);
	IMAGE_SECTION_HEADER CurrentSection = { 0 };
	for (WORD SectionIndex = 0; SectionIndex < NtHeader->FileHeader.NumberOfSections; SectionIndex++) {
		CurrentSection = SectionsOfFile[SectionIndex];
		if (CurrentSection.VirtualAddress <= RelativeVa && CurrentSection.VirtualAddress + CurrentSection.SizeOfRawData > RelativeVa) {
			VaOfRva = (ULONG64)DriverDataBase + (ULONG64)(RelativeVa + (CurrentSection.PointerToRawData - CurrentSection.VirtualAddress));  // Memory address of driver + rva + size of the sections unused (non-raw) data
			if (!Silent) {
				printf("[SUC] RvaToActualVa, found the section, RVA of %lu, section VA of %lu and size of raw data of %lu, VA of RVA: %llu ..\n", RelativeVa, CurrentSection.VirtualAddress, CurrentSection.SizeOfRawData, VaOfRva);
			}
			return VaOfRva;
		}
	}
	VaOfRva = (ULONG64)DriverDataBase + (ULONG64)RelativeVa;
	if (!Silent) {
		printf("[SUC] RvaToActualVa, did not find the section, RVA of %lu, driver data base address of %p, VA of RVA: %llu ..\n", RelativeVa, DriverDataBase, VaOfRva);
	}
	return VaOfRva;
}


BOOL CheckDriver(const char* DriverPath, BOOL Debug) {
	printf("[INF] CheckDriver, Checking driver %s ..\n", DriverPath);

	// Read the driver file data into a memory buffer (base address in memory) -
	HANDLE DriverFile = CreateFileA(
		DriverPath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (DriverFile == INVALID_HANDLE_VALUE) {
		std::cerr << "[ERR] CheckDriver, cannot create driver file handle: " << GetLastError() << "\n";
		return FALSE;
	}
	printf("[SUC] CheckDriver, got driver file handle ..\n");

	PVOID DriverData = malloc((SIZE_T)GetFileSize(DriverFile, NULL));
	if (DriverData == NULL) {
		printf("[ERR] CheckDriver, cannot allocate memory for driver data\n");
		CloseHandle(DriverFile);
		return FALSE;
	}
	printf("[SUC] CheckDriver, allocated driver file buffer ..\n");

	DWORD DriverBytesRead = 0;
	BOOL ReadRes = ReadFile(
		DriverFile,
		DriverData,
		GetFileSize(DriverFile, NULL),
		&DriverBytesRead,
		NULL);

	if (!ReadRes) {
		std::cerr << "[ERR] CheckDriver, cannot read driver file data into memory buffer: " << GetLastError() << "\n";
		free(DriverData);
		CloseHandle(DriverFile);
		return FALSE;
	}

	if (DriverBytesRead != GetFileSize(DriverFile, NULL)) {
		printf("[ERR] CheckDriver, read %lu bytes instead of %lu bytes of driver file data\n", DriverBytesRead, GetFileSize(DriverFile, NULL));
		free(DriverData);
		CloseHandle(DriverFile);
		return FALSE;
	}
	CloseHandle(DriverFile);
	printf("[SUC] CheckDriver, success in reading the driver file data (proceeding into analyzing imports) ..\n");


	// Get import data of driver file -
	PIMAGE_NT_HEADERS NtHeader = GetNtHeader(DriverData, FALSE);
	if (NtHeader == NULL) {
		printf("[ERR] CheckDriver, failed getting the NT header of the driver file\n");
		// free(DriverData);
		return FALSE;
	}

	if (NtHeader->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE) {
		printf("[ERR] CheckDriver, subsystem specified in NT header is %u instead of %u (IMAGE_SUBSYSTEM_NATIVE)\n", NtHeader->OptionalHeader.Subsystem, (WORD)IMAGE_SUBSYSTEM_NATIVE);
		free(DriverData);
		return FALSE;
	}
	printf("[SUC] CheckDriver, success in getting NT header (now getting import directory from optional header) ..\n");

	IMAGE_DATA_DIRECTORY ImportDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ImportDirectory.Size == 0 || ImportDirectory.VirtualAddress == NULL) {
		printf("[ERR] CheckDriver, import directory size = 0 / VA = NULL\n");
		free(DriverData);
		return FALSE;
	}
	printf("[SUC] CheckDriver, success in getting import directory from optional header ..\n");

	const char* CurrName = NULL;
	const char* CurrFuncName = NULL;
	BOOL MdlFound = FALSE;
	BOOL DrvFound = FALSE;
	IMAGE_THUNK_DATA* CurrImportedFunc = { 0 };
	IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)RvaToActualVa(DriverData, ImportDirectory.VirtualAddress, TRUE);  // Get the import descriptor with the data about all of the imported functions
	for (int it = 0; ImportDescriptor->Name != NULL; ImportDescriptor++) {
		CurrName = (const char*)RvaToActualVa(DriverData, ImportDescriptor->Name, TRUE);  // Get the name of the current import-from module
		if (strcmp(CurrName, source_module) != 0) {
			printf("[INF] CheckDriver, nonmatching source module names, actual: %s != expected: %s, moving on ..\n", CurrName, source_module);
			continue;  // source of import is not the kernel
		}

		if (ImportDescriptor->OriginalFirstThunk != NULL) {
			// descriptor.OriginalFirstThunk contains the RVA of function names in the IAT like expected:
			printf("[INF] CheckDriver, RVA of IAT function names is in descriptor.OriginalFirstThunk like expected\n");
			CurrImportedFunc = (IMAGE_THUNK_DATA*)RvaToActualVa(DriverData, ImportDescriptor->OriginalFirstThunk, TRUE);
		}
		else {
			// descriptor.FirstThunk contains the RVA of function names in the IAT:
			printf("[INF] CheckDriver, RVA of IAT function names is in descriptor.FirstThunk (special case)\n");
			CurrImportedFunc = (IMAGE_THUNK_DATA*)RvaToActualVa(DriverData, ImportDescriptor->FirstThunk, TRUE);
		}

		// iterate through the function names to find matches for vulnuravle functions -
		printf("\n-------------------");
		printf("\nIMPORTED FUNCTIONS:");
		printf("\n-------------------\n");
		for (int itr = 0; CurrImportedFunc->u1.AddressOfData != NULL; CurrImportedFunc++) {
			if (CurrImportedFunc->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				// Function is identified by an ordinal (a special number) and not a name:
				printf("[INF] CheckDriver, current function in IAT is ordinal, moving on ..\n");
				continue;
			}

			CurrFuncName = ((IMAGE_IMPORT_BY_NAME*)(RvaToActualVa(DriverData, (DWORD)CurrImportedFunc->u1.AddressOfData, TRUE)))->Name;  // Get imported function name
			if (Debug) {
				printf("[INF] CheckDriver, current function name in IAT is %s\n", CurrFuncName);
			}
			
			for (int vulnfunc = 0; vulnfunc < sizeof(search_imports) / sizeof(const char*); vulnfunc++) {
				if (strcmp(CurrFuncName, search_imports[vulnfunc]) == 0) {
					printf("\n%s:\n  Vulnurable Function, RVA = %p\n", CurrFuncName, (PVOID)CurrImportedFunc->u1.AddressOfData);
					if (!DrvFound) {
						DrvFound = TRUE;
						WriteResultsFile(DriverPath, CurrFuncName, TRUE);
					}
					else {
						WriteResultsFile(DriverPath, CurrFuncName, FALSE);
					}

					if (!MdlFound) {
						MdlFound = TRUE;
					}
				}
			}
			printf("\n%s:\n  Not Vulnurable\n", CurrFuncName);
		}
		if (!MdlFound) {
			printf("[INF] CheckDriver, no imported function from module %s, driver %s were found to be vulnurable ..\n", CurrName, DriverPath);
		}
		else {
			MdlFound = FALSE;
		}
	}
	if (!DrvFound) {
		printf("[FIN] CheckDriver, no imported function from driver %s were found to be vulnurable at all, finishing function ..\n", DriverPath);
		free(DriverData);
		return FALSE;
	}
	free(DriverData);
	return TRUE;
}


PVOID AddGroup(PVOID ExistingBuffer, const char* AddPath, SIZE_T ExistingSize) {
	char Divider = '~';
	PVOID BufferName = NULL;
	PVOID NewBuffer = NULL;


	// Add a specific path to the group buffer:
	if (ExistingBuffer == NULL || ExistingSize == 0) {
		NewBuffer = malloc(strlen(AddPath));
		if (NewBuffer == NULL) {
			return NULL;
		}
		memcpy(NewBuffer, AddPath, strlen(AddPath));
		return NewBuffer;
	}
	NewBuffer = malloc(ExistingSize + strlen(AddPath) + 1);
	if (NewBuffer == NULL) {
		return NULL;
	}
	memcpy(NewBuffer, ExistingBuffer, ExistingSize);
	memcpy((PVOID)((ULONG64)NewBuffer + ExistingSize), &Divider, 1);
	memcpy((PVOID)((ULONG64)NewBuffer + ExistingSize + 1), AddPath, strlen(AddPath));
	free(ExistingBuffer);
	return NewBuffer;
}


void PrintAllGroup(PVOID Buffer, SIZE_T BufferSize) {
	char CurrentChar = NULL;
	char NullTerminator = '\0';
	ULONG64 LastStart = 0;
	PVOID CurrentName = NULL;


	// Iterate over all saved names from group list:
	for (SIZE_T CharIndex = 0; CharIndex < BufferSize; CharIndex++) {
		CurrentChar = ((char*)Buffer)[CharIndex];
		if (CurrentChar == '~') {
			CurrentName = malloc(CharIndex - (SIZE_T)LastStart + 1);
			if (CurrentName == NULL) {
				printf("(null)\n");
				continue;
			}
			memcpy(CurrentName, (PVOID)((ULONG64)Buffer + LastStart), CharIndex - (SIZE_T)LastStart);
			memcpy((PVOID)((ULONG64)CurrentName + CharIndex - (SIZE_T)LastStart), &NullTerminator, 1);
			printf("%s\n", (char*)CurrentName);
			free(CurrentName);
			LastStart = (ULONG64)CharIndex + 1;
		}
	}
	free(Buffer);
}


int PerformSingleScan(char* ScanPath) {
	HANDLE ResultsFile = INVALID_HANDLE_VALUE;
	BOOL IsCurrentVulnerable = FALSE;
	PVOID NoVulnerableBuffer = NULL;
	PVOID VulnerableBuffer = NULL;
	SIZE_T NoVulnerableSize = 0;
	SIZE_T VulnerableSize = 0;
	if (ScanPath == NULL) {
		printf("PerformSingleScan() - invalid parameters\n");
		return ERROR_INVALID_PARAMETER;
	}
	ResultsFile = CreateFileA(
		"vulnerable_driver_report.txt",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (VulnRes == INVALID_HANDLE_VALUE) {
		printf("PerformSingleScan() - CreateFileA(): %d\n", GetLastError());
	}


	// Iterate over all files recursively:
	printf("Searching for drivers in path %s ..\n", ScanPath);
	for (const auto& file : std::filesystem::recursive_directory_iterator(ScanPath)) {
		if (!std::filesystem::is_regular_file(file.path())) {
			continue;
		}
		if (file.path().extension() != ".sys") {
			continue;
		}
		IsCurrentVulnerable = CheckDriver(file.path().string().c_str(), FALSE);
		if (!IsCurrentVulnerable) {
			NoVulnerableBuffer = AddGroup(NoVulnerableBuffer, file.path().string().c_str(), NoVulnerableSize);
			NoVulnerableSize += strlen(file.path().string().c_str());
			if (NoVulnerableSize != 0) {
				NoVulnerableSize++;
			}
		}
		else {
			VulnerableBuffer = AddGroup(VulnerableBuffer, file.path().string().c_str(), VulnerableSize);
			VulnerableSize += strlen(file.path().string().c_str());
			if (VulnerableSize != 0) {
				VulnerableSize++;
			}
		}
	}
	CloseHandle(VulnRes);


	// Print out the results:
	printf("\n========");
	printf("\nSINGLE SCAN RESULTS:");
	printf("\n========\n");
	printf("\nDrivers that could be vulnurable:\n");
	PrintAllGroup(VulnerableBuffer, VulnerableSize);
	printf("\nDrivers that probably are not vulnurable:\n");
	PrintAllGroup(NoVulnerableBuffer, NoVulnerableSize);
}


int PerformFullScan() {
	HANDLE ResultsFile = INVALID_HANDLE_VALUE;
	BOOL IsCurrentVulnerable = FALSE;
	PVOID NoVulnerableBuffer = NULL;
	PVOID VulnerableBuffer = NULL;
	SIZE_T NoVulnerableSize = 0;
	SIZE_T VulnerableSize = 0;
	if (ScanPath == NULL) {
		printf("PerformSingleScan() - invalid parameters\n");
		return ERROR_INVALID_PARAMETER;
	}
	ResultsFile = CreateFileA(
		"vulnerable_driver_report.txt",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (VulnRes == INVALID_HANDLE_VALUE) {
		printf("PerformSingleScan() - CreateFileA(): %d\n", GetLastError());
	}


	// Iterate over all files recursively:
	printf("Searching for drivers in path %s ..\n", ScanPath);
	for (const auto& file : std::filesystem::recursive_directory_iterator(ScanPath)) {
		if (!std::filesystem::is_regular_file(file.path())) {
			continue;
		}
		if (file.path().extension() != ".sys") {
			continue;
		}
		IsCurrentVulnerable = CheckDriver(file.path().string().c_str(), FALSE);
		if (!IsCurrentVulnerable) {
			NoVulnerableBuffer = AddGroup(NoVulnerableBuffer, file.path().string().c_str(), NoVulnerableSize);
			NoVulnerableSize += strlen(file.path().string().c_str());
			if (NoVulnerableSize != 0) {
				NoVulnerableSize++;
			}
		}
		else {
			VulnerableBuffer = AddGroup(VulnerableBuffer, file.path().string().c_str(), VulnerableSize);
			VulnerableSize += strlen(file.path().string().c_str());
			if (VulnerableSize != 0) {
				VulnerableSize++;
			}
		}
	}
	CloseHandle(VulnRes);


	// Print out the results:
	printf("\n========");
	printf("\nSINGLE SCAN RESULTS:");
	printf("\n========\n");
	printf("\nDrivers that could be vulnurable:\n");
	PrintAllGroup(VulnerableBuffer, VulnerableSize);
	printf("\nDrivers that probably are not vulnurable:\n");
	PrintAllGroup(NoVulnerableBuffer, NoVulnerableSize);
}


int PerformCustomScan(char* CustomListPath) {
	HANDLE ResultsFile = INVALID_HANDLE_VALUE;
	BOOL IsCurrentVulnerable = FALSE;
	PVOID NoVulnerableBuffer = NULL;
	PVOID VulnerableBuffer = NULL;
	SIZE_T NoVulnerableSize = 0;
	SIZE_T VulnerableSize = 0;
	if (ScanPath == NULL) {
		printf("PerformSingleScan() - invalid parameters\n");
		return ERROR_INVALID_PARAMETER;
	}
	ResultsFile = CreateFileA(
		"vulnerable_driver_report.txt",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (VulnRes == INVALID_HANDLE_VALUE) {
		printf("PerformSingleScan() - CreateFileA(): %d\n", GetLastError());
	}


	// Iterate over all files recursively:
	printf("Searching for drivers in path %s ..\n", ScanPath);
	for (const auto& file : std::filesystem::recursive_directory_iterator(ScanPath)) {
		if (!std::filesystem::is_regular_file(file.path())) {
			continue;
		}
		if (file.path().extension() != ".sys") {
			continue;
		}
		IsCurrentVulnerable = CheckDriver(file.path().string().c_str(), FALSE);
		if (!IsCurrentVulnerable) {
			NoVulnerableBuffer = AddGroup(NoVulnerableBuffer, file.path().string().c_str(), NoVulnerableSize);
			NoVulnerableSize += strlen(file.path().string().c_str());
			if (NoVulnerableSize != 0) {
				NoVulnerableSize++;
			}
		}
		else {
			VulnerableBuffer = AddGroup(VulnerableBuffer, file.path().string().c_str(), VulnerableSize);
			VulnerableSize += strlen(file.path().string().c_str());
			if (VulnerableSize != 0) {
				VulnerableSize++;
			}
		}
	}
	CloseHandle(VulnRes);


	// Print out the results:
	printf("\n========");
	printf("\nSINGLE SCAN RESULTS:");
	printf("\n========\n");
	printf("\nDrivers that could be vulnurable:\n");
	PrintAllGroup(VulnerableBuffer, VulnerableSize);
	printf("\nDrivers that probably are not vulnurable:\n");
	PrintAllGroup(NoVulnerableBuffer, NoVulnerableSize);
}


void PrintHelp() {
	printf("\n========");
	printf("\nOptions for vulnerable driver scanning:");
	printf("\n1) full-scan on all of the known paths on a computer (\"VulnDrvScan.exe --iterate-full-scan\")");
	printf("\n2) single-scan on all files recursively inside main path (\"VulnDrvScan.exe --iterate-single-scan main_path\")");
	printf("\n3) custom-scan with file listing specific file/folder paths to scan (\"VulnDrvScan.exe --iterate-custom-scan custom_list_path\")");
	printf("\n========\n");
}


int main(int argc, char* argv[]) {
	printf("[STR] Path to searching directory:\n");
	const char* SearchPathAct = "H:\\research_list\\";
	SIZE_T VulSize = 0;
	SIZE_T NoVulSize = 0;
	PVOID VulBuf = NULL;
	PVOID NoVulBuf = NULL;
	BOOL CurrVul = FALSE;


	// Check if parameters match the required full-scan, single-scan or custom-scan requirements:
	if (argc != 2 && argc != 3) {
		PrintHelp();
		return ERROR_INVALID_PARAMETER;
	}
	if (strcmp(argv[1], "--iterate-full-scan")) {
		return PerformFullScan();
	}
	if (strcmp(argv[1], "--iterate-single-scan")) {
		std::string MainPath = argv[2];
		if (!pathExists(MainPath)) {
			printf("main() - main path %s does not exist\n", argv[2]);
			PrintHelp();
			return ERROR_INVALID_PARAMETER;
		}
		return PerformSingleScan(argv[2]);
	}
	if (strcmp(argv[1], "--iterate-custom-scan")) {
		std::string CustomFilePath = argv[2];
		if (!pathExists(CustomFilePath)) {
			printf("main() - custom list path %s does not exist\n", argv[2]);
			PrintHelp();
			return ERROR_INVALID_PARAMETER;
		}
		return PerformCustomScan(argv[2]);
	}
	PrintHelp();
	return ERROR_INVALID_PARAMETER;
}