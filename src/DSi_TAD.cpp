/*
    Copyright 2016-2026 melonDS team

    This file is part of melonDS.

    melonDS is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    melonDS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with melonDS. If not, see http://www.gnu.org/licenses/.
*/

#include "DSi_TAD.h"

#include <cstring>

#include "Platform.h"
#include "sha1/sha1.hpp"
#include "tiny-AES-c/aes.hpp"

namespace melonDS::DSi_TAD
{

using DSi_TMD::TitleMetadata;

// AES-CBC keys used to decrypt the title key stored in DSiWare tickets.
// These are the DSi "common keys" (AES keyslot 3Dh), as derived for retail
// and debug consoles. They are part of the publicly documented DSi
// cryptography (see GBATEK: "DSi SD/MMC DSiware ... Tickets and Title
// metadata"); the retail keys are the same on every console.
// Each entry is tried in turn until the content SHA1 from the TMD matches.
static const u8 CommonKeys[][16] =
{
    // key_3Dh.0.retail ("app" key)
    {0x64,0xC5,0xFD,0x55,0xDD,0x3A,0xD9,0x88,0x32,0x5B,0xAA,0xEC,0x52,0x43,0xDB,0x98},
    // key_3Dh.1.retail ("system" key)
    {0x4A,0xAA,0x3D,0x0E,0x27,0xD4,0xD7,0x28,0xD0,0xB1,0xB4,0x33,0xF0,0xF9,0xCB,0xC8},
    // key_3Dh.2.retail
    {0xFB,0xB0,0xEF,0x8C,0xDB,0xB0,0xD8,0xE4,0x53,0xCD,0x99,0x34,0x43,0x71,0x69,0x7F},
    // key_3Dh.3.retail
    {0x25,0x95,0x9B,0x7A,0xD0,0x40,0x9F,0x72,0x68,0x41,0x98,0xBA,0x2E,0xCD,0x7D,0xC6},
    // key_3Dh.4.retail
    {0x7A,0xDA,0x22,0xCA,0xFF,0xC4,0x76,0xCC,0x82,0x97,0xA0,0xC7,0xCE,0xEE,0xEE,0xBE},
    // key_3Dh.5.retail
    {0xA5,0x05,0x1C,0xA1,0xB3,0x7D,0xCF,0x3A,0xFB,0xCF,0x8C,0xC1,0xED,0xD9,0xCE,0x02},
    // key_3Dh.0.debug
    {0x55,0xA3,0xF8,0x72,0xBD,0xC8,0x0C,0x55,0x5A,0x65,0x43,0x81,0x13,0x9E,0x15,0x3B},
    // key_3Dh.1.debug
    {0x44,0x34,0xED,0x14,0x82,0x0C,0xA1,0xEB,0xAB,0x82,0xC1,0x6E,0x7B,0xEF,0x0C,0x25},
    // key_3Dh.2.debug
    {0xF6,0x2E,0x3F,0x95,0x8E,0x28,0xA2,0x1F,0x28,0x9E,0xEC,0x71,0xA8,0x66,0x29,0xDC},
    // key_3Dh.3.debug
    {0x2B,0x49,0xCB,0x6F,0x99,0x98,0xD9,0xAD,0x94,0xF2,0xED,0xE7,0xB5,0xDA,0x3E,0x27},
    // key_3Dh.4.debug
    {0x75,0x05,0x52,0xBF,0xAA,0x1C,0x04,0x07,0x55,0xC8,0xD5,0x9A,0x55,0xF9,0xAD,0x1F},
    // key_3Dh.5.debug
    {0xAA,0xDA,0x4C,0xA8,0xF6,0xE5,0xA9,0x77,0xE0,0xA0,0xF9,0xE4,0x76,0xCF,0x0D,0x63},
};
static constexpr size_t NumCommonKeys = sizeof(CommonKeys) / sizeof(CommonKeys[0]);

static u32 ReadBE32(const u8* p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static u64 ReadBE64(const u8* p)
{
    return ((u64)ReadBE32(p) << 32) | ReadBE32(p + 4);
}

static void AESCBCDecrypt(const u8 key[16], const u8 iv[16], u8* data, u32 len)
{
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, data, len);
}

bool ImportTAD(const std::string& path,
               std::vector<u8>& appOut,
               TitleMetadata& tmdOut,
               std::string& errorOut)
{
    auto fail = [&errorOut](const char* msg) { errorOut = msg; return false; };

    Platform::FileHandle* f = Platform::OpenFile(path, Platform::FileMode::Read);
    if (!f)
        return fail("Could not open the .tad file.");

    u8 hdr[0x40];
    if (Platform::FileRead(hdr, 1, sizeof(hdr), f) != sizeof(hdr))
    {
        Platform::CloseFile(f);
        return fail("File is too small to be a .tad container.");
    }

    const u32 hdrSize    = ReadBE32(hdr + 0x00);
    const u32 certSize   = ReadBE32(hdr + 0x08);
    const u32 crlSize    = ReadBE32(hdr + 0x0C);
    const u32 ticketSize = ReadBE32(hdr + 0x10);
    const u32 tmdSize    = ReadBE32(hdr + 0x14);
    const u32 contentSize = ReadBE32(hdr + 0x18);

    if (hdrSize < 0x20)
    {
        Platform::CloseFile(f);
        return fail("Malformed .tad header.");
    }

    auto align64 = [](u32 v) { return (v + 63) & ~63u; };

    Platform::FileSeek(f, 0, Platform::FileSeekOrigin::End);
    const u64 fileLen = Platform::FilePosition(f);

    const u64 ticketOff = 0x40 + align64(certSize) + align64(crlSize);
    const u64 tmdOff    = ticketOff + align64(ticketSize);
    const u64 contentOff = tmdOff + align64(tmdSize);

    if (ticketSize < 0x2A4 || tmdSize < sizeof(TitleMetadata) ||
        contentOff > fileLen || (u64)contentOff + contentSize > fileLen)
    {
        Platform::CloseFile(f);
        return fail("Malformed .tad section layout.");
    }

    // --- ticket ---
    std::vector<u8> ticket(ticketSize);
    Platform::FileSeek(f, ticketOff, Platform::FileSeekOrigin::Start);
    if (Platform::FileRead(ticket.data(), 1, ticketSize, f) != ticketSize)
    {
        Platform::CloseFile(f);
        return fail("Could not read the ticket.");
    }

    const u8* encTitleKey = &ticket[0x1BF];
    const u8* ticketTitleId = &ticket[0x1DC];

    // --- title metadata ---
    Platform::FileSeek(f, tmdOff, Platform::FileSeekOrigin::Start);
    if (Platform::FileRead(&tmdOut, sizeof(TitleMetadata), 1, f) != 1)
    {
        Platform::CloseFile(f);
        return fail("Could not read the title metadata.");
    }

    Platform::CloseFile(f);

    // NumberOfContents is big-endian on disk but the struct is read raw,
    // so byte-swap the native u16 before comparing.
    const u32 numContents = ((tmdOut.NumberOfContents & 0xFF) << 8)
                          | (tmdOut.NumberOfContents >> 8);
    if (numContents != 1)
        return fail("Only single-content titles are supported.");

    const DSi_TMD::TitleMetadataContent& content = tmdOut.Contents;
    const u64 realContentSize = ReadBE64(content.ContentSize);
    const u32 contentIndex = ((u32)content.ContentIndex[0] << 8) | content.ContentIndex[1];

    if (realContentSize > contentSize || realContentSize == 0 || (realContentSize & 15))
        return fail("Malformed content size in title metadata.");

    // the ticket and the TMD must agree on the title
    const u8* tmdTitleId = &tmdOut.TitleId[0];
    for (int i = 0; i < 8; i++)
    {
        if (ticketTitleId[i] != tmdTitleId[i])
            return fail("Ticket/title-metadata title ID mismatch.");
    }

    // --- encrypted content ---
    // re-open to keep the read code simple; content can be several MB
    f = Platform::OpenFile(path, Platform::FileMode::Read);
    if (!f)
        return fail("Could not re-open the .tad file.");

    std::vector<u8> enc((size_t)realContentSize);
    Platform::FileSeek(f, contentOff, Platform::FileSeekOrigin::Start);
    if (Platform::FileRead(enc.data(), 1, enc.size(), f) != enc.size())
    {
        Platform::CloseFile(f);
        return fail("Could not read the title content.");
    }
    Platform::CloseFile(f);

    // --- decryption ---
    // Title key: AES-CBC, key = common key, IV = title ID || zeros.
    // Content:   AES-CBC, key = title key,  IV = content index || zeros.
    u8 iv[16] = {0};
    memcpy(iv, ticketTitleId, 8);

    u8 ivContent[16] = {0};
    ivContent[0] = content.ContentIndex[0];
    ivContent[1] = content.ContentIndex[1];

    for (size_t k = 0; k < NumCommonKeys; k++)
    {
        u8 titleKey[16];
        memcpy(titleKey, encTitleKey, 16);
        AESCBCDecrypt(CommonKeys[k], iv, titleKey, 16);

        std::vector<u8> dec = enc;
        AESCBCDecrypt(titleKey, ivContent, dec.data(), (u32)dec.size());

        u8 digest[20];
        SHA1_CTX sha;
        SHA1Init(&sha);
        SHA1Update(&sha, dec.data(), (u32)dec.size());
        SHA1Final(digest, &sha);

        if (!memcmp(digest, content.ContentSha1Hash, 20))
        {
            appOut = std::move(dec);
            return true;
        }
    }

    return fail("Could not decrypt the title: no known common key matches "
                "(the .tad may use an internal/non-retail key).");
}

}
