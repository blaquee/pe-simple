#include <Windows.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <iomanip>
#include <sstream>

struct FileHandle
{
    HANDLE hFile;
    FileHandle(HANDLE a) :hFile(a) {}
    ~FileHandle() {
        if (hFile)
            CloseHandle(hFile);
    }
};

DWORD OffsetToRva(PIMAGE_NT_HEADERS nt, DWORD offset)
{
    return 0;
}

DWORD RvaToOffset(PIMAGE_NT_HEADERS nt, DWORD rva)
{
    int i;
    WORD nSections;
    PIMAGE_SECTION_HEADER pSectionHeader;

    pSectionHeader = IMAGE_FIRST_SECTION(nt);
    nSections = nt->FileHeader.NumberOfSections;

    for (i = 0; i < nSections; i++)
    {
        if (pSectionHeader->VirtualAddress <= rva)
            if ((pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize) > rva)
            {
                rva -= pSectionHeader->VirtualAddress;
                rva += pSectionHeader->PointerToRawData;
                return rva;
            }
        pSectionHeader++;
    }
}

int main(int argc, char** argv)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;

    PIMAGE_DATA_DIRECTORY pDataDir;
    
    std::vector<IMAGE_SECTION_HEADER> pSections;

    HANDLE hMap;
    HANDLE hMapView;
    LPVOID lpMapBase;

    DWORD peOffset;
    DWORD entryPoint;


    if (argc < 2)
    {
        std::cout << "Not enough arguments" << std::endl;
        return 0;
    }

    std::string fileName(argv[1]);

    HANDLE hFile = CreateFileA(fileName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "Bad file" << std::endl;
        return 0;
    }
    //Scoped Handle
    FileHandle f(hFile);

    hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap)
    {
        std::cout << "No Mapping" << std::endl;
        return 0;
    }

    lpMapBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!lpMapBase)
    {
        std::cout << "No Mapped File" << std::endl;
        return 0;
    }

    pDosHeader = static_cast<PIMAGE_DOS_HEADER>(lpMapBase);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "Not Valid DOS Sig" << std::endl;
        UnmapViewOfFile(lpMapBase);
        return 0;
    }

    pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "Not Valid PE File" << std::endl;
        UnmapViewOfFile(lpMapBase);
        return 0;
    }

    entryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;

    //Read the sections
    IMAGE_SECTION_HEADER pSecHeader;
    int nNumSections = pNtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER dwSectionPointer = IMAGE_FIRST_SECTION(pNtHeader);

    for (int i = 0; i < nNumSections; i++)
    {
        if ((dwSectionPointer->SizeOfRawData > 0) && (dwSectionPointer->PointerToRawData > 0))
        //Copy the section
            memcpy(&pSecHeader, (char*)dwSectionPointer,
                    sizeof(IMAGE_SECTION_HEADER));

            pSections.push_back(pSecHeader);
            dwSectionPointer++;
    }

    //Summarize findings
    std::ostringstream output;
    output << "File Information" << std::endl;
    output << "EntryPoint: " << std::hex << entryPoint << std::endl;
    output << "Section Information" << std::endl;
    output << "Name" << std::setw(8) << "VirtualAddress" << std::setw(15) << "Size" << std::setw(8)  << std::endl;

    auto begin = pSections.cbegin();
    auto end = pSections.cend();
    while (begin != end)
    {
        output << begin->Name << std::setw(8) << begin->VirtualAddress << std::setw(15)  << begin->SizeOfRawData
            << std::setw(8) << std::endl;
        ++begin;
    }

    std::cout << output.str() << std::endl;
    UnmapViewOfFile(lpMapBase);
    std::cin.get();

    return 0;
}