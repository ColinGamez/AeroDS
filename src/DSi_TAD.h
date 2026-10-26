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

#ifndef DSI_TAD_H
#define DSI_TAD_H

#include "types.h"
#include "DSi_TMD.h"
#include <string>
#include <vector>

namespace melonDS::DSi_TAD
{

/// Imports a DSiWare title from a .tad container (the WAD-family format used
/// for DSiWare on Nintendo's servers, SD card imports and leaked/dev masters).
///
/// The container is parsed, its ticket title key is decrypted with the known
/// DSi common keys, the content is decrypted and verified against the SHA1
/// stored in the title metadata. Only titles with exactly one content are
/// supported (which is all DSiWare in practice).
///
/// @param path     Path to the .tad file.
/// @param appOut   Receives the decrypted .app payload on success.
/// @param tmdOut   Receives the title metadata on success.
/// @param errorOut Human-readable error message on failure.
/// @return true on success.
bool ImportTAD(const std::string& path,
               std::vector<u8>& appOut,
               DSi_TMD::TitleMetadata& tmdOut,
               std::string& errorOut);

}

#endif // DSI_TAD_H
