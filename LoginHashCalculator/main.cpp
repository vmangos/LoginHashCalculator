#include "Common.h"
#include "Crypto/HMACSHA1.h"
#include <windows.h>
#include <fstream>
#include <iterator>
#include <vector>
#include <array>

enum GameVersion
{
    VERSION_NONE      = 0,
    VERSION_VANILLA   = 1,
    VERSION_EARLY_TBC = 2,
    VERSION_LATE_TBC  = 3,
    VERSION_CATACLYSM = 4
};

static uint32 g_gameVersion = VERSION_VANILLA;

std::array<uint8, 16> g_versionProof = { { 0xBA, 0xA3, 0x1E, 0x99, 0xA0, 0x0B, 0x21, 0x57, 0xFC, 0x37, 0x3F, 0xB3, 0x69, 0xCD, 0xD2, 0xF1 } };

template<typename T, typename U>
inline T AlignValueUp(T value, U alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

std::vector<uint8> ReadBinaryFile(std::string const& name)
{
    std::vector<uint8> binary;
    std::ifstream binaryFile(name, std::ifstream::binary);
    if (!binaryFile)
        return binary;

    binaryFile >> std::noskipws;
    binaryFile.seekg(0, std::ios_base::end);
    binary.resize(std::vector<uint8>::size_type(binaryFile.tellg()));
    binaryFile.seekg(0, std::ios_base::beg);
    binaryFile.read(reinterpret_cast<char*>(binary.data()), binary.size());
    return binary;
}

void AppendBinaryChecksum(HMACSHA1& hmac, std::string const& name)
{
    std::vector<uint8> binary = ReadBinaryFile(name);
    if (binary.empty())
        return;

    hmac.UpdateData(binary.data(), binary.size());
}

void PrintHash(uint8 const* digest)
{
    FILE* pTextFile = fopen("hash.txt", "w");
    printf("Hash for this game version:\n");
    for (uint32 i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        uint8 byte = digest[i];

        printf("%02X ", byte & 0xff);

        if (pTextFile)
        {
            if (i != 0)
                fprintf(pTextFile, ", ");

            fprintf(pTextFile, "0x%02X", byte & 0xff);
        }
    }

    if (pTextFile)
        fclose(pTextFile);
}

namespace Windows
{
    enum WowChecksumElementType
    {
        IMPORTS = 0,
        IMPORTS_DESCRIPTOR = 1,
        RELOCATION = 2,
        HEADER = 3,
    };

    struct WowChecksumElement
    {
        uint32 Offset;
        uint32 Size;
        union
        {
            struct
            {
                uint32 OriginalFirstThunk;
            } Imports;

            struct
            {
                uint32 RelocationType;
            } Relocation;
        };

        uint32 Type;
    };

    DWORD RvaToFileOffset(IMAGE_NT_HEADERS32 const* pe, DWORD rva)
    {
        IMAGE_SECTION_HEADER const* section = IMAGE_FIRST_SECTION(pe);
        for (WORD i = 0; i < pe->FileHeader.NumberOfSections; ++i)
        {
            if (rva >= section[i].VirtualAddress && rva <= (section[i].VirtualAddress + section[i].Misc.VirtualSize))
                return rva - section[i].VirtualAddress + section[i].PointerToRawData;
        }

        return -1;
    }

    DWORD RvaToFileOffset(IMAGE_NT_HEADERS64 const* pe, DWORD rva)
    {
        IMAGE_SECTION_HEADER const* section = IMAGE_FIRST_SECTION(pe);
        for (WORD i = 0; i < pe->FileHeader.NumberOfSections; ++i)
        {
            if (rva >= section[i].VirtualAddress && rva <= (section[i].VirtualAddress + section[i].Misc.VirtualSize))
                return rva - section[i].VirtualAddress + section[i].PointerToRawData;
        }

        return -1;
    }

    void CollectHeaders(std::vector<WowChecksumElement>& checksumElements)
    {
        WowChecksumElement element;
        element.Offset = offsetof(IMAGE_DOS_HEADER, e_csum);
        element.Size = sizeof(IMAGE_DOS_HEADER::e_csum);
        element.Type = HEADER;
        checksumElements.emplace_back(element);
    }

    template<typename NT_HEADERS>
    void CollectRelocations(std::vector<WowChecksumElement>& checksumElements, std::vector<uint8> const& executable, NT_HEADERS const* pe)
    {
        IMAGE_DATA_DIRECTORY const* relocations = &pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!relocations->VirtualAddress || !relocations->Size)
            return;

        DWORD relocationsOffset = RvaToFileOffset(pe, relocations->VirtualAddress);
        if (relocationsOffset == -1)
            return;

        IMAGE_BASE_RELOCATION const* relocation = reinterpret_cast<IMAGE_BASE_RELOCATION const*>(&executable[relocationsOffset]);
        IMAGE_BASE_RELOCATION const* relocationEnd = relocation + (relocations->Size / sizeof(IMAGE_BASE_RELOCATION));
        while (relocation < relocationEnd)
        {
            if (!relocation->SizeOfBlock)
                break;

            uint32 count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16);
            relocationsOffset += sizeof(IMAGE_BASE_RELOCATION);
            while (count)
            {
                uint16 const* relocationInfo = reinterpret_cast<uint16 const*>(&executable[relocationsOffset]);
                switch (*relocationInfo >> 12)
                {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        break;
                    case IMAGE_REL_BASED_HIGH:
                    case IMAGE_REL_BASED_LOW:
                    {
                        WowChecksumElement relocationElement;
                        relocationElement.Offset = RvaToFileOffset(pe, relocation->VirtualAddress) + (*relocationInfo & 0xFFF);
                        relocationElement.Size = sizeof(uint16);
                        relocationElement.Relocation.RelocationType = *relocationInfo >> 12;
                        relocationElement.Type = RELOCATION;
                        checksumElements.emplace_back(relocationElement);
                        break;
                    }
                    case IMAGE_REL_BASED_HIGHLOW:
                    {
                        WowChecksumElement relocationElement;
                        relocationElement.Offset = RvaToFileOffset(pe, relocation->VirtualAddress) + (*relocationInfo & 0xFFF);
                        relocationElement.Size = sizeof(uint32);
                        relocationElement.Relocation.RelocationType = *relocationInfo >> 12;
                        relocationElement.Type = RELOCATION;
                        checksumElements.emplace_back(relocationElement);
                        break;
                    }
                    case IMAGE_REL_BASED_DIR64:
                    {
                        WowChecksumElement relocationElement;
                        relocationElement.Offset = RvaToFileOffset(pe, relocation->VirtualAddress) + (*relocationInfo & 0xFFF);
                        relocationElement.Size = sizeof(uint64);
                        relocationElement.Relocation.RelocationType = *relocationInfo >> 12;
                        relocationElement.Type = RELOCATION;
                        checksumElements.emplace_back(relocationElement);
                        break;
                    }
                    default:
                        return;
                }
                relocationsOffset += sizeof(uint16);
                --count;
            }

            relocation = reinterpret_cast<IMAGE_BASE_RELOCATION const*>(&executable[relocationsOffset]);
        }
    }

    void CollectImports(std::vector<WowChecksumElement>& checksumElements, std::vector<uint8> const& executable, IMAGE_NT_HEADERS32 const* pe)
    {
        IMAGE_DATA_DIRECTORY const* imports = &pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imports->Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
            return;

        DWORD importsOffset = RvaToFileOffset(pe, imports->VirtualAddress);
        if (importsOffset == -1)
            return;

        IMAGE_IMPORT_DESCRIPTOR const* importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR const*>(&executable[importsOffset]);
        IMAGE_IMPORT_DESCRIPTOR const* importDescriptorEnd = importDescriptor + (imports->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));
        while (importDescriptor < importDescriptorEnd)
        {
            DWORD nameOffset = RvaToFileOffset(pe, importDescriptor->Name);
            if (nameOffset != -1)
            {
                char const* importName = reinterpret_cast<char const*>(&executable[nameOffset]);
                if (!importName[0])
                    break;

                IMAGE_THUNK_DATA32 const* importEntry = reinterpret_cast<IMAGE_THUNK_DATA32 const*>(&executable[RvaToFileOffset(pe, importDescriptor->FirstThunk)]);
                IMAGE_THUNK_DATA32 const* importEntriesItr = importEntry;
                while (importEntriesItr->u1.AddressOfData)
                    ++importEntriesItr;

                WowChecksumElement importsElement;
                importsElement.Offset = RvaToFileOffset(pe, importDescriptor->FirstThunk);
                importsElement.Imports.OriginalFirstThunk = importDescriptor->OriginalFirstThunk ? RvaToFileOffset(pe, importDescriptor->OriginalFirstThunk) : 0;
                importsElement.Size = 4 * uint32(importEntriesItr - importEntry) + 4;
                importsElement.Type = IMPORTS;
                checksumElements.emplace_back(importsElement);

                WowChecksumElement importDirectoryElement;
                importDirectoryElement.Offset = importsOffset;
                importDirectoryElement.Size = sizeof(IMAGE_IMPORT_DESCRIPTOR);
                importDirectoryElement.Type = IMPORTS_DESCRIPTOR;
                checksumElements.emplace_back(importDirectoryElement);
            }
            ++importDescriptor;
            importsOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    void CollectImports(std::vector<WowChecksumElement>& checksumElements, std::vector<uint8> const& executable, IMAGE_NT_HEADERS64 const* pe)
    {
        IMAGE_DATA_DIRECTORY const* imports = &pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imports->Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
            return;

        DWORD importsOffset = RvaToFileOffset(pe, imports->VirtualAddress);
        if (importsOffset == -1)
            return;

        IMAGE_IMPORT_DESCRIPTOR const* importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR const*>(&executable[importsOffset]);
        IMAGE_IMPORT_DESCRIPTOR const* importDescriptorEnd = importDescriptor + (imports->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));
        while (importDescriptor < importDescriptorEnd)
        {
            DWORD nameOffset = RvaToFileOffset(pe, importDescriptor->Name);
            if (nameOffset != -1)
            {
                char const* importName = reinterpret_cast<char const*>(&executable[nameOffset]);
                if (!importName[0])
                    break;

                IMAGE_THUNK_DATA64 const* importEntry = reinterpret_cast<IMAGE_THUNK_DATA64 const*>(&executable[RvaToFileOffset(pe, importDescriptor->FirstThunk)]);
                IMAGE_THUNK_DATA64 const* importEntriesItr = importEntry;
                while (importEntriesItr->u1.AddressOfData)
                    ++importEntriesItr;

                WowChecksumElement importsElement;
                importsElement.Offset = RvaToFileOffset(pe, importDescriptor->FirstThunk);
                importsElement.Imports.OriginalFirstThunk = importDescriptor->OriginalFirstThunk ? RvaToFileOffset(pe, importDescriptor->OriginalFirstThunk) : 0;
                importsElement.Size = 8 * uint32(importEntriesItr - importEntry) + 8;
                importsElement.Type = IMPORTS;
                checksumElements.emplace_back(importsElement);

                WowChecksumElement importDirectoryElement;
                importDirectoryElement.Offset = importsOffset;
                importDirectoryElement.Size = sizeof(IMAGE_IMPORT_DESCRIPTOR);
                importDirectoryElement.Type = IMPORTS_DESCRIPTOR;
                checksumElements.emplace_back(importDirectoryElement);
            }
            ++importDescriptor;
            importsOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    void UpdateZeros(HMACSHA1& hmac, std::size_t count)
    {
        uint8 zeros[0x1000] = {};
        std::size_t updated = 0x1000;
        for (std::size_t i = count; i; i -= updated)
        {
            if (i < 0x1000)
                updated = i;

            hmac.UpdateData(zeros, updated);
        }
    }

    void UpdateChecksumElement(HMACSHA1& hmac, WowChecksumElement const& element, std::vector<uint8> const& executable, uint32 pointer)
    {
        switch (element.Type)
        {
            case IMPORTS:
            {
                if (element.Imports.OriginalFirstThunk)
                    hmac.UpdateData(&executable[element.Imports.OriginalFirstThunk], element.Size);
                else
                    UpdateZeros(hmac, element.Size);
                break;
            }
            case IMPORTS_DESCRIPTOR:
            {
                IMAGE_IMPORT_DESCRIPTOR descriptor = *reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR const*>(&executable[pointer]);
                descriptor.TimeDateStamp = 0;
                descriptor.ForwarderChain = 0;
                hmac.UpdateData(reinterpret_cast<uint8 const*>(&descriptor), sizeof(IMAGE_IMPORT_DESCRIPTOR));
                break;
            }
            case RELOCATION:
                hmac.UpdateData(&executable[pointer], element.Size);
                break;
            case HEADER:
                UpdateZeros(hmac, element.Size);
                break;
            default:
                break;
        }
    }

    void ChecksumSection(HMACSHA1& hmac, std::vector<WowChecksumElement> const& checksumElements, std::vector<uint8> const& executable, IMAGE_SECTION_HEADER const* section, uint32 sectionAlignment, uint32 fileAlignment)
    {
        DWORD sizeWithAlignment = AlignValueUp(section->Misc.VirtualSize, sectionAlignment);
        if (section->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            UpdateZeros(hmac, sizeWithAlignment);
            return;
        }

        auto pred = [](WowChecksumElement const& left, DWORD right)
        {
            return left.Offset < right;
        };

        auto checksumElementBegin = std::lower_bound(checksumElements.begin(), checksumElements.end(), section->PointerToRawData, pred);
        auto checksumElementEnd = std::lower_bound(checksumElements.begin(), checksumElements.end(), section->PointerToRawData + section->Misc.VirtualSize, pred);

        if (section->Misc.VirtualSize)
        {
            DWORD pointer = section->PointerToRawData;
            while (pointer < section->PointerToRawData + section->Misc.VirtualSize)
            {
                DWORD size = section->Misc.VirtualSize + section->PointerToRawData - pointer;
                if (checksumElementBegin != checksumElementEnd)
                    size = checksumElementBegin->Offset - pointer;

                if (size)
                {
                    hmac.UpdateData(&executable[pointer], size);
                    pointer += size;
                }
                else
                {
                    UpdateChecksumElement(hmac, *checksumElementBegin, executable, pointer);
                    pointer += checksumElementBegin->Size;
                    ++checksumElementBegin;
                }
            }
        }

        checksumElementEnd = std::lower_bound(checksumElements.begin(), checksumElements.end(), section->PointerToRawData + AlignValueUp(section->SizeOfRawData, fileAlignment), pred);

        if (DWORD alignmentPad = (sizeWithAlignment - section->Misc.VirtualSize))
        {
            std::vector<uint8> padding;
            padding.resize(alignmentPad);

            DWORD pointer = 0;
            while (pointer < alignmentPad)
            {
                DWORD size = alignmentPad - pointer;
                if (checksumElementBegin != checksumElementEnd)
                    size = checksumElementBegin->Offset - section->PointerToRawData - section->SizeOfRawData - pointer;

                if (size)
                {
                    hmac.UpdateData(&padding[pointer], size);
                    pointer += size;
                }
                else
                {
                    UpdateChecksumElement(hmac, *checksumElementBegin, executable, pointer);
                    pointer += checksumElementBegin->Size;
                    ++checksumElementBegin;
                }
            }
        }
    }

    void AppendExecutableChecksum(HMACSHA1& hmac, std::string const& name)
    {
        std::vector<uint8> executable = ReadBinaryFile(name);
        if (executable.empty())
        {
            printf("Could not open %s\n", name.c_str());
            return;
        }

        printf("Processing %s\n", name.c_str());
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(executable.data());
        IMAGE_NT_HEADERS32* pe = reinterpret_cast<IMAGE_NT_HEADERS32*>(&executable[dos->e_lfanew]);
        IMAGE_NT_HEADERS64* pe64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(&executable[dos->e_lfanew]);
        std::vector<WowChecksumElement> checksumElements;
        CollectHeaders(checksumElements);
        DWORD sizeOfHeaders;
        DWORD fileAlignment;
        DWORD sectionAlignment;

        if (pe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            sizeOfHeaders = pe->OptionalHeader.SizeOfHeaders;
            fileAlignment = pe->OptionalHeader.FileAlignment;
            sectionAlignment = pe->OptionalHeader.SectionAlignment;
            CollectRelocations(checksumElements, executable, pe);
            CollectImports(checksumElements, executable, pe);
        }
        else
        {
            sizeOfHeaders = pe64->OptionalHeader.SizeOfHeaders;
            fileAlignment = pe64->OptionalHeader.FileAlignment;
            sectionAlignment = pe64->OptionalHeader.SectionAlignment;
            CollectRelocations(checksumElements, executable, pe64);
            CollectImports(checksumElements, executable, pe64);
        }
        std::sort(checksumElements.begin(), checksumElements.end(), [](WowChecksumElement const& left, WowChecksumElement const& right)
        {
            return left.Offset < right.Offset;
        });

        IMAGE_SECTION_HEADER headerFakeSection;
        std::fill(std::begin(headerFakeSection.Name), std::end(headerFakeSection.Name), 0);
        headerFakeSection.Misc.VirtualSize = sizeOfHeaders;
        headerFakeSection.VirtualAddress = 0;
        headerFakeSection.SizeOfRawData = AlignValueUp(sizeOfHeaders, fileAlignment);
        headerFakeSection.PointerToRawData = 0;
        headerFakeSection.PointerToRelocations = 0;
        headerFakeSection.PointerToLinenumbers = 0;
        headerFakeSection.NumberOfRelocations = 0;
        headerFakeSection.NumberOfLinenumbers = 0;
        headerFakeSection.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

        ChecksumSection(hmac, checksumElements, executable, &headerFakeSection, sectionAlignment, fileAlignment);

        IMAGE_SECTION_HEADER const* section = IMAGE_FIRST_SECTION(pe);
        for (WORD i = 0; i < pe->FileHeader.NumberOfSections; ++i)
            ChecksumSection(hmac, checksumElements, executable, section + i, sectionAlignment, fileAlignment);
    }

    void CalculateInstallChecksum()
    {
        HMACSHA1 hmac(g_versionProof.data(), uint32(g_versionProof.size()));

        if (g_gameVersion > VERSION_VANILLA)
        {
            AppendExecutableChecksum(hmac, "./Wow.exe");

            if (g_gameVersion < VERSION_CATACLYSM)
                AppendExecutableChecksum(hmac, "./DivxDecoder.dll");

            if (g_gameVersion < VERSION_LATE_TBC)
                AppendExecutableChecksum(hmac, "./fmod.dll");
        }
        else
        {
            AppendBinaryChecksum(hmac, "./Wow.exe");
            AppendBinaryChecksum(hmac, "./fmod.dll");
            AppendBinaryChecksum(hmac, "./ijl15.dll");
            AppendBinaryChecksum(hmac, "./dbghelp.dll");
        }
        AppendBinaryChecksum(hmac, "./unicows.dll");

        hmac.Finalize();

        PrintHash(hmac.GetDigest());
    }
}

namespace Mac
{
    void CalculateInstallChecksum()
    {
        HMACSHA1 hmac(g_versionProof.data(), uint32(g_versionProof.size()));
        AppendBinaryChecksum(hmac, "./World of Warcraft.app/Contents/MacOS/World of Warcraft");
        AppendBinaryChecksum(hmac, "./World of Warcraft.app/Contents/Info.plist");
        if (g_gameVersion > VERSION_VANILLA)
        {
            AppendBinaryChecksum(hmac, "./World of Warcraft.app/Contents/Resources/DivX Gaming.component/Contents/Info.plist");

            if (g_gameVersion < VERSION_CATACLYSM)
                AppendBinaryChecksum(hmac, "./World of Warcraft.app/Contents/Resources/DivX Gaming.component/Contents/MacOS/DivX Gaming");

            AppendBinaryChecksum(hmac, "./World of Warcraft.app/Contents/Resources/DivX Gaming.component/Contents/PkgInfo");
        }
        AppendBinaryChecksum(hmac, "./World of Warcraft.app/Contents/Resources/Main.nib/objects.xib");
        AppendBinaryChecksum(hmac, "./World of Warcraft.app/Contents/Resources/wow.icns");
        AppendBinaryChecksum(hmac, "./World of Warcraft.app/Contents/PkgInfo");
        hmac.Finalize();

        PrintHash(hmac.GetDigest());
    }
}

int main()
{
    printf("Select game version.\n");
    printf("1. 1.0.0 to 1.12.2\n");
    printf("2. 1.12.3 to 2.1.3\n");
    printf("3. 2.2.0 to 3.3.5\n");
    printf("4. 4.0.1+\n");
    printf("> ");
    scanf_s("%u", &g_gameVersion);
    
    printf("Select platform.\n");
    printf("1. Windows\n");
    printf("2. MacOS\n");
    printf("> ");
    uint32 platform = 0;
    scanf_s("%u", &platform);

    switch (platform)
    {
        case 1:
            Windows::CalculateInstallChecksum();
            break;
        case 2:
            Mac::CalculateInstallChecksum();
            break;
    }

    fseek(stdin, 0, SEEK_END);
    getchar();
    return 0;
}