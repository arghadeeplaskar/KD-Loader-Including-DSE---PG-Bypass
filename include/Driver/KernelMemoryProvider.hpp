#pragma once

#include <Common/Types.hpp>
#include <filesystem>

namespace Agdl::Drivers
{
    class AgdlServiceManager
    {
    public:
        explicit AgdlServiceManager(
            std::string serviceName,
            std::filesystem::path binaryPath
        );
        ~AgdlServiceManager();

        AgdlServiceManager(const AgdlServiceManager&) = delete;
        AgdlServiceManager& operator=(const AgdlServiceManager&) = delete;

        AgdlServiceManager(AgdlServiceManager&&) noexcept;
        AgdlServiceManager& operator=(AgdlServiceManager&&) noexcept;

        [[nodiscard]] bool Start() noexcept;
        [[nodiscard]] bool Stop() noexcept;
        [[nodiscard]] bool IsElevated() const noexcept;

    private:
        std::string           m_serviceName;
        std::filesystem::path m_binaryPath;
        bool                  m_serviceCreated{ false };

        [[nodiscard]] bool CreateServiceEntry() noexcept;
        [[nodiscard]] bool DeleteServiceEntry() noexcept;
    };

    class AgdlKernelMemoryProvider
    {
    public:
        explicit AgdlKernelMemoryProvider(
            std::string driverName,
            std::string deviceName
        );
        ~AgdlKernelMemoryProvider();

        AgdlKernelMemoryProvider(const AgdlKernelMemoryProvider&) = delete;
        AgdlKernelMemoryProvider& operator=(const AgdlKernelMemoryProvider&) = delete;

        [[nodiscard]] bool Initialize() noexcept;
        [[nodiscard]] bool IsReady() const noexcept { return m_deviceHandle != INVALID_HANDLE_VALUE; }

        [[nodiscard]] bool Read(
            Common::Address_t kernelAddress,
            PVOID outBuffer,
            std::size_t size
        ) noexcept;

        [[nodiscard]] bool Write(
            Common::Address_t kernelAddress,
            const void* inBuffer,
            std::size_t size
        ) noexcept;

        template <typename T>
        [[nodiscard]] bool WriteValue(Common::Address_t kernelAddress, const T& value) noexcept
        {
            return Write(kernelAddress, std::addressof(value), sizeof(T));
        }

        template <typename T>
        [[nodiscard]] std::optional<T> ReadValue(Common::Address_t kernelAddress) noexcept
        {
            T buffer{};
            if (Read(kernelAddress, std::addressof(buffer), sizeof(T)))
            {
                return buffer;
            }
            return std::nullopt;
        }

    private:
        std::string           m_driverName;
        std::string           m_deviceName;
        std::filesystem::path m_driverPath;
        HANDLE                m_deviceHandle{ INVALID_HANDLE_VALUE };
        std::unique_ptr<AgdlServiceManager> m_serviceManager;
    };
}
