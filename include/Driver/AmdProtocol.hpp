#pragma once

#include <Common/Types.hpp>

namespace Agdl::Drivers
{
    // Agdl Hardware abstraction for AMD PDFW driver primitives
    constexpr DWORD FILE_DEVICE_AMD_PDFW = 0x8000;
    constexpr DWORD PDFW_MEMCPY_FUNC      = 0x805;

    constexpr DWORD IOCTL_AMDPDFW_MEMCPY = CTL_CODE(
        FILE_DEVICE_AMD_PDFW,
        PDFW_MEMCPY_FUNC,
        METHOD_BUFFERED,
        FILE_ANY_ACCESS
    );

#pragma pack(push, 1)
    struct AgdlPdfwPacket
    {
        std::uint8_t Reserved[16]{ 0 };
        PVOID Destination{ nullptr };
        PVOID Source{ nullptr };
        PVOID Reserved2{ nullptr };
        DWORD Size{ 0 };
        DWORD Reserved3{ 0 };
    };
#pragma pack(pop)

    class AgdlAmdProtocol
    {
    public:
        static bool CopyVirtualMemory(
            HANDLE deviceHandle,
            PVOID destination,
            PVOID source,
            std::size_t byteCount
        ) noexcept;
    };
}
