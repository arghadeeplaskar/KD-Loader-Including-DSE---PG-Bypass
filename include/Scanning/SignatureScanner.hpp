#pragma once

#include <Common/Types.hpp>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <filesystem>

namespace Agdl::Scanning
{
    struct AgdlSignaturePattern
    {
        std::string Name;
        std::vector<std::optional<std::uint8_t>> Bytes;

        static AgdlSignaturePattern Parse(std::string name, std::string_view idaSignature);
    };

    class AgdlModuleScanner
    {
    public:
        explicit AgdlModuleScanner(const std::filesystem::path& imagePath);
        ~AgdlModuleScanner();

        AgdlModuleScanner(const AgdlModuleScanner&) = delete;
        AgdlModuleScanner& operator=(const AgdlModuleScanner&) = delete;

        [[nodiscard]] bool IsLoaded() const noexcept { return m_mappedBase != nullptr; }
        [[nodiscard]] Common::Address_t GetBaseAddress() const noexcept { return reinterpret_cast<Common::Address_t>(m_mappedBase); }
        [[nodiscard]] std::size_t GetImageSize() const noexcept { return m_imageSize; }

        [[nodiscard]] std::optional<Common::AgdlMemoryRegion> GetSection(std::string_view sectionName) const noexcept;
        [[nodiscard]] Common::Address_t FindPattern(const AgdlSignaturePattern& pattern, std::string_view sectionName = "") const noexcept;

    private:
        HMODULE     m_mappedBase{ nullptr };
        std::size_t m_imageSize{ 0 };
    };
}
