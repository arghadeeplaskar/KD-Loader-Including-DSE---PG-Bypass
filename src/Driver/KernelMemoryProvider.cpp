#include <Driver/KernelMemoryProvider.hpp>
#include <Driver/AmdProtocol.hpp>
#include <iostream>

namespace Agdl::Drivers
{
    AgdlServiceManager::AgdlServiceManager(
        std::string serviceName,
        std::filesystem::path binaryPath
    ) : m_serviceName(std::move(serviceName)),
        m_binaryPath(std::move(binaryPath))
    {
    }

    AgdlServiceManager::~AgdlServiceManager()
    {
        Stop();
        DeleteServiceEntry();
    }

    AgdlServiceManager::AgdlServiceManager(AgdlServiceManager&& other) noexcept
        : m_serviceName(std::move(other.m_serviceName)),
          m_binaryPath(std::move(other.m_binaryPath)),
          m_serviceCreated(other.m_serviceCreated)
    {
        other.m_serviceCreated = false;
    }

    AgdlServiceManager& AgdlServiceManager::operator=(AgdlServiceManager&& other) noexcept
    {
        if (this != &other)
        {
            Stop();
            DeleteServiceEntry();

            m_serviceName = std::move(other.m_serviceName);
            m_binaryPath = std::move(other.m_binaryPath);
            m_serviceCreated = other.m_serviceCreated;
            other.m_serviceCreated = false;
        }
        return *this;
    }

    bool AgdlServiceManager::IsElevated() const noexcept
    {
        HANDLE tokenHandle = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
        {
            return false;
        }

        DWORD lengthNeeded = 0;
        GetTokenInformation(tokenHandle, TokenIntegrityLevel, nullptr, 0, &lengthNeeded);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            CloseHandle(tokenHandle);
            return false;
        }

        auto pLabel = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(LocalAlloc(LPTR, lengthNeeded));
        if (!pLabel)
        {
            CloseHandle(tokenHandle);
            return false;
        }

        bool isElevated = false;
        if (GetTokenInformation(tokenHandle, TokenIntegrityLevel, pLabel, lengthNeeded, &lengthNeeded))
        {
            const DWORD subAuthCount = *GetSidSubAuthorityCount(pLabel->Label.Sid);
            const DWORD integrityLevel = *GetSidSubAuthority(pLabel->Label.Sid, subAuthCount - 1);
            isElevated = (integrityLevel >= SECURITY_MANDATORY_HIGH_RID);
        }

        LocalFree(pLabel);
        CloseHandle(tokenHandle);
        return isElevated;
    }

    bool AgdlServiceManager::CreateServiceEntry() noexcept
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return false;

        const std::string pathStr = m_binaryPath.string();
        SC_HANDLE service = CreateServiceA(
            scm,
            m_serviceName.c_str(),
            m_serviceName.c_str(),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            pathStr.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr
        );

        if (!service)
        {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
            {
                service = OpenServiceA(scm, m_serviceName.c_str(), SERVICE_ALL_ACCESS);
            }
        }

        if (service)
        {
            m_serviceCreated = true;
            CloseServiceHandle(service);
        }

        CloseServiceHandle(scm);
        return m_serviceCreated;
    }

    bool AgdlServiceManager::DeleteServiceEntry() noexcept
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return false;

        SC_HANDLE service = OpenServiceA(scm, m_serviceName.c_str(), DELETE);
        bool success = false;
        if (service)
        {
            success = (DeleteService(service) != FALSE);
            CloseServiceHandle(service);
        }

        CloseServiceHandle(scm);
        m_serviceCreated = false;
        return success;
    }

    bool AgdlServiceManager::Start() noexcept
    {
        if (!CreateServiceEntry())
        {
            return false;
        }

        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return false;

        SC_HANDLE service = OpenServiceA(scm, m_serviceName.c_str(), SERVICE_START);
        bool success = false;
        if (service)
        {
            if (StartServiceA(service, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
            {
                success = true;
            }
            CloseServiceHandle(service);
        }

        CloseServiceHandle(scm);
        return success;
    }

    bool AgdlServiceManager::Stop() noexcept
    {
        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return false;

        SC_HANDLE service = OpenServiceA(scm, m_serviceName.c_str(), SERVICE_STOP);
        bool success = false;
        if (service)
        {
            SERVICE_STATUS status{};
            success = (ControlService(service, SERVICE_CONTROL_STOP, &status) != FALSE);
            CloseServiceHandle(service);
        }

        CloseServiceHandle(scm);
        return success;
    }

    AgdlKernelMemoryProvider::AgdlKernelMemoryProvider(
        std::string driverName,
        std::string deviceName
    ) : m_driverName(std::move(driverName)),
        m_deviceName(std::move(deviceName))
    {
        m_driverPath = std::filesystem::current_path() / m_driverName;
        m_serviceManager = std::make_unique<AgdlServiceManager>("AgdlKernelService", m_driverPath);
    }

    AgdlKernelMemoryProvider::~AgdlKernelMemoryProvider()
    {
        if (m_deviceHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(m_deviceHandle);
            m_deviceHandle = INVALID_HANDLE_VALUE;
        }
    }

    bool AgdlKernelMemoryProvider::Initialize() noexcept
    {
        if (!m_serviceManager->IsElevated())
        {
            std::cerr << "[-] [Agdl] Administrator rights required to register kernel services.\n";
            return false;
        }

        const std::string devicePath = "\\\\.\\" + m_deviceName;
        m_deviceHandle = CreateFileA(
            devicePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (m_deviceHandle == INVALID_HANDLE_VALUE)
        {
            if (!std::filesystem::exists(m_driverPath))
            {
                std::cerr << "[-] [Agdl] Driver binary missing: " << m_driverPath << "\n";
                return false;
            }

            if (!m_serviceManager->Start())
            {
                std::cerr << "[-] [Agdl] Failed initializing driver service.\n";
                return false;
            }

            m_deviceHandle = CreateFileA(
                devicePath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );
        }

        return (m_deviceHandle != INVALID_HANDLE_VALUE);
    }

    bool AgdlKernelMemoryProvider::Read(
        Common::Address_t kernelAddress,
        PVOID outBuffer,
        std::size_t size
    ) noexcept
    {
        if (!IsReady() && !Initialize())
        {
            return false;
        }

        return AgdlAmdProtocol::CopyVirtualMemory(
            m_deviceHandle,
            outBuffer,
            reinterpret_cast<PVOID>(kernelAddress),
            size
        );
    }

    bool AgdlKernelMemoryProvider::Write(
        Common::Address_t kernelAddress,
        const void* inBuffer,
        std::size_t size
    ) noexcept
    {
        if (!IsReady() && !Initialize())
        {
            return false;
        }

        return AgdlAmdProtocol::CopyVirtualMemory(
            m_deviceHandle,
            reinterpret_cast<PVOID>(kernelAddress),
            const_cast<PVOID>(inBuffer),
            size
        );
    }
}
