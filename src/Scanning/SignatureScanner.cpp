#include <Scanning/SignatureScanner.hpp>
#include <Psapi.h>
#include <sstream>
#include <algorithm>

namespace Agdl::Scanning
{
    AgdlSignaturePattern AgdlSignaturePattern::Parse(std::string name, std::string_view idaSignature)
    {
        AgdlSignaturePattern result;
        result.Name = std::move(name);

        std::stringstream ss{ std::string(idaSignature) };
        std::string token;

        while (ss >> token)
        {
            if (token == "?" || token == "??")
            {
                result.Bytes.push_back(std::nullopt);
            }
            else
            {
                const auto byteValue = static_cast<std::uint8_t>(std::strtoul(token.c_str(), nullptr, 16));
                result.Bytes.push_back(byteValue);
            }
        }

        return result;
    }

    AgdlModuleScanner::AgdlModuleScanner(const std::filesystem::path& imagePath)
    {
        m_mappedBase = LoadLibraryExW(imagePath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (m_mappedBase)
        {
            MODULEINFO mi{};
            if (GetModuleInformation(GetCurrentProcess(), m_mappedBase, &mi, sizeof(mi)))
            {
                m_imageSize = mi.SizeOfImage;
            }
        }
    }

    AgdlModuleScanner::~AgdlModuleScanner()
    {
        if (m_mappedBase)
        {
            FreeLibrary(m_mappedBase);
            m_mappedBase = nullptr;
        }
    }

    std::optional<Common::AgdlMemoryRegion> AgdlModuleScanner::GetSection(std::string_view sectionName) const noexcept
    {
        if (!IsLoaded()) return std::nullopt;

        const auto base = reinterpret_cast<const std::uint8_t*>(m_mappedBase);
        const auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

        const auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

        const auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            const char* currentName = reinterpret_cast<const char*>(sectionHeader[i].Name);
            if (sectionName.compare(0, sectionName.length(), currentName, sectionName.length()) == 0)
            {
                return Common::AgdlMemoryRegion{
                    .BaseAddress = reinterpret_cast<Common::Address_t>(base + sectionHeader[i].VirtualAddress),
                    .RegionSize  = sectionHeader[i].Misc.VirtualSize
                };
            }
        }

        return std::nullopt;
    }

    Common::Address_t AgdlModuleScanner::FindPattern(
        const AgdlSignaturePattern& pattern,
        std::string_view sectionName
    ) const noexcept
    {
        if (!IsLoaded() || pattern.Bytes.empty()) return Common::InvalidAddress;

        Common::Address_t searchStart = 0;
        std::size_t searchSize = 0;

        if (!sectionName.empty())
        {
            auto section = GetSection(sectionName);
            if (!section) return Common::InvalidAddress;
            searchStart = section->BaseAddress;
            searchSize  = section->RegionSize;
        }
        else
        {
            searchStart = GetBaseAddress();
            searchSize  = m_imageSize;
        }

        if (searchSize < pattern.Bytes.size()) return Common::InvalidAddress;

        const auto memory = reinterpret_cast<const std::uint8_t*>(searchStart);
        const auto patternLength = pattern.Bytes.size();
        const auto endScan = searchSize - patternLength;

        for (std::size_t i = 0; i <= endScan; ++i)
        {
            bool match = true;
            for (std::size_t p = 0; p < patternLength; ++p)
            {
                if (pattern.Bytes[p].has_value() && pattern.Bytes[p].value() != memory[i + p])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return searchStart + i;
            }
        }

        return Common::InvalidAddress;
    }
}
