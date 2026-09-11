#pragma once

#include <string>
#include <optional>

#include <winrt/Windows.Foundation.h>
#include <common/version/helper.h>

namespace updating
{
    winrt::Windows::Foundation::IAsyncOperation<bool> uninstall_previous_msix_version_async();

    // Verifies that the installer at installerPath is a PowerToys installer.
    //
    // The downloaded installer lives in a user-writable directory
    // (%LOCALAPPDATA%\Microsoft\PowerToys\Updates), but it is executed elevated. This check
    // must therefore be performed in the elevated context immediately before launching the
    // installer to prevent a local attacker from swapping in a malicious installer (TOCTOU)
    // and gaining elevation.
    //
    // verifiedFileHandle, when non-null, is kept open by the caller with sharing that denies
    // write/delete to other processes. The identity check is performed before the handle is
    // released, closing the time-of-check / time-of-use window for the elevated launch.
    bool verify_installer_trust(const std::wstring& installerPath, void* verifiedFileHandle = nullptr);
}
