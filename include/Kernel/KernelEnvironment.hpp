#pragma once

#include <Common/Types.hpp>
#include <Scanning/SignatureScanner.hpp>
#include <optional>

namespace Agdl::Kernel
{
    struct AgdlSystemOffsets
    {
        Common::Offset_t SeValidateImageHeader{ 0 };
        Common::Offset_t SeValidateImageData{ 0 };
        Common::Offset_t RetGadget{ 0 };
        Common::Offset_t PatchGuardCallback{ 0 };
        Common::Offset_t PatchGuardZeroValue{ 0 };

        [[nodiscard]] bool IsComplete() const noexcept
        {
            return SeValidateImageHeader != 0 &&
                   SeValidateImageData != 0 &&
                   RetGadget != 0 &&
                   PatchGuardCallback != 0 &&
                   PatchGuardZeroValue != 0;
        }
    };

    class AgdlKernelEnvironment
    {
    public:
        [[nodiscard]] static Common::Address_t GetKernelBase() noexcept;
        [[nodiscard]] static std::optional<AgdlSystemOffsets> ResolveOffsets(const Scanning::AgdlModuleScanner& kernelImage) noexcept;

    private:
        [[nodiscard]] static Common::Offset_t ResolveRipRelative(
            Common::Address_t matchAddress,
            std::uint32_t ripOffsetFromMatch,
            std::uint32_t instructionLength,
            Common::Address_t imageBase
        ) noexcept;
    };
}
