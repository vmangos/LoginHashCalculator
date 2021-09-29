#include "Crypto\HMACSHA1.h"

// This is the version challenge that is hardcoded in realmd.
uint8 const g_versionChallenge[] = { 0xBA, 0xA3, 0x1E, 0x99, 0xA0, 0x0B, 0x21, 0x57, 0xFC, 0x37, 0x3F, 0xB3, 0x69, 0xCD, 0xD2, 0xF1 };

int main()
{
    // this file list is for vanilla only
    std::vector<std::string> clientFileNames { "WoW.exe", "fmod.dll", "ijl15.dll", "dbghelp.dll", "unicows.dll" };
    std::vector<uint8> buffer;

    for (auto const& fileName : clientFileNames)
    {
        FILE* pClientFile = fopen(fileName.c_str(), "rb");
        if (pClientFile == nullptr)
        {
            printf("Can't open %s.\n", fileName.c_str());
            return 1;
        }

        // check file size
        fseek(pClientFile, 0, SEEK_END);
        auto const size = ftell(pClientFile);
        fseek(pClientFile, 0, SEEK_SET);

        // expand buffer
        auto const oldBufferSize = buffer.size();
        buffer.resize(size + buffer.size());

        // read the file into the buffer
        fread(buffer.data() + oldBufferSize, 1, size, pClientFile);
        fclose(pClientFile);
    }

    // calculate the hash
    HMACSHA1 hash(g_versionChallenge, sizeof(g_versionChallenge) * sizeof(uint8));
    hash.UpdateData(buffer);
    hash.Finalize();
    uint8* digest = hash.GetDigest();

    // output the hash
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

    getchar();
    return 0;
}