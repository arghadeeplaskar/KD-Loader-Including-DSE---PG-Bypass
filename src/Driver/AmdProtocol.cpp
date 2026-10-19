#include <Driver/AmdProtocol.hpp>

namespace Agdl::Drivers
{
    bool AgdlAmdProtocol::CopyVirtualMemory(
        HANDLE deviceHandle,
        PVOID destination,
        PVOID source,
        std::size_t byteCount
    ) noexcept
    {
        if (deviceHandle == INVALID_HANDLE_VALUE || !destination || !source || byteCount == 0)
        {
            return false;
        }

        AgdlPdfwPacket packet{};
        packet.Destination = destination;
        packet.Source      = source;
        packet.Size        = static_cast<DWORD>(byteCount);

        DWORD bytesReturned = 0;
        const BOOL success = DeviceIoControl(
            deviceHandle,
            IOCTL_AMDPDFW_MEMCPY,
            &packet,
            sizeof(packet),
            &packet,
            sizeof(packet),
            &bytesReturned,
            nullptr
        );

        return success != FALSE;
    }
}
