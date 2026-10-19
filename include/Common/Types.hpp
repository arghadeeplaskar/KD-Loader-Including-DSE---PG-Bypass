#pragma once

#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <span>

namespace Agdl::Common
{
    using Address_t = std::uintptr_t;
    using Offset_t  = std::uint32_t;
    using ByteSpan  = std::span<const std::uint8_t>;

    constexpr Address_t InvalidAddress = 0;

    struct AgdlMemoryRegion
    {
        Address_t BaseAddress{ InvalidAddress };
        std::size_t RegionSize{ 0 };

        [[nodiscard]] constexpr bool Contains(Address_t address) const noexcept
        {
            return (address >= BaseAddress) && (address < (BaseAddress + RegionSize));
        }

        [[nodiscard]] constexpr bool IsValid() const noexcept
        {
            return BaseAddress != InvalidAddress && RegionSize > 0;
        }
    };
}
