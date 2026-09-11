#include "pch.h"

#include "installer.h"
#include <common/version/version.h>
#include <common/utils/MsiUtils.h>
#include <common/utils/os-detect.h>
#include "utils/winapi_error.h"

#include <common/logger/logger.h>

#include <cstdio>
#include <vector>

#include <winver.h>
#include <MsiQuery.h>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "Msi.lib")

namespace // Strings in this namespace should not be localized
{
    const wchar_t DONT_SHOW_AGAIN_RECORD_REGISTRY_PATH[] = L"delete_previous_powertoys_confirm";

    const wchar_t TOAST_TITLE[] = L"PowerToys";

    const wchar_t MSIX_PACKAGE_NAME[] = L"Microsoft.PowerToys";
    const wchar_t MSIX_PACKAGE_PUBLISHER[] = L"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
}

namespace updating
{
    winrt::Windows::Foundation::IAsyncOperation<bool> uninstall_previous_msix_version_async()
    {
        winrt::Windows::Management::Deployment::PackageManager package_manager;

        try
        {
            auto packages = package_manager.FindPackagesForUser({}, MSIX_PACKAGE_NAME, MSIX_PACKAGE_PUBLISHER);
            VersionHelper current_version(VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION, VERSION_BUILD);

            for (auto package : packages)
            {
                VersionHelper msix_version(package.Id().Version().Major, package.Id().Version().Minor, package.Id().Version().Build, package.Id().Version().Revision);

                if (msix_version < current_version)
                {
                    co_await package_manager.RemovePackageAsync(package.Id().FullName());
                    co_return true;
                }
            }
        }
        catch (...)
        {
        }
        co_return false;
    }

    namespace
    {
        // Identity anchors for the official PowerToys installer. These are compile-time constants
        // (never read from the attacker-writable UpdateState.json or from the network), so the
        // identity check also holds for fully offline updates. The .exe bootstrapper version
        // resource reports ProductName "PowerToys (Preview) <arch>"; the .msi UpgradeCodes are
        // shared with MsiUtils.h.
        // NOTE: This must match the WiX bundle ProductName ("PowerToys (Preview) <arch>", see
        // installer/PowerToysSetupVNext/PowerToys.wxs). It is intentionally a prefix so the trailing
        // architecture varies. If the product is ever renamed (e.g. a stable/GA build that drops
        // "(Preview)"), this constant MUST be updated in lockstep, otherwise a legitimate installer
        // would be rejected here in the elevated update path.
        constexpr const wchar_t* POWERTOYS_PRODUCT_NAME_PREFIX = L"PowerToys (Preview)";

        std::wstring read_version_string(const std::vector<BYTE>& versionInfo, WORD language, WORD codePage, const wchar_t* name)
        {
            wchar_t subBlock[128];
            swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s", language, codePage, name);

            LPVOID value = nullptr;
            UINT valueLen = 0;
            if (VerQueryValueW(versionInfo.data(), subBlock, &value, &valueLen) && value != nullptr && valueLen > 0)
            {
                std::wstring result{ static_cast<const wchar_t*>(value), valueLen };
                result.resize(wcslen(result.c_str()));
                return result;
            }
            return {};
        }

        // .exe (WiX bootstrapper) identity: version resource ProductName must start with
        // "PowerToys (Preview)".
        bool exe_version_info_is_powertoys(const std::wstring& installerPath)
        {
            DWORD ignoredHandle = 0;
            const DWORD size = GetFileVersionInfoSizeW(installerPath.c_str(), &ignoredHandle);
            if (size == 0)
            {
                Logger::error(L"Installer '{}' has no version resource (error {:#x})", installerPath, GetLastError());
                return false;
            }

            std::vector<BYTE> versionInfo(size);
            if (!GetFileVersionInfoW(installerPath.c_str(), 0, size, versionInfo.data()))
            {
                Logger::error(L"Couldn't read the version resource of installer '{}' (error {:#x})", installerPath, GetLastError());
                return false;
            }

            struct LangAndCodePage
            {
                WORD language;
                WORD codePage;
            };
            LangAndCodePage* translations = nullptr;
            UINT translationsBytes = 0;
            if (!VerQueryValueW(versionInfo.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<LPVOID*>(&translations), &translationsBytes) ||
                translations == nullptr || translationsBytes < sizeof(LangAndCodePage))
            {
                Logger::error(L"Installer '{}' version resource has no translation table", installerPath);
                return false;
            }

            const size_t translationCount = translationsBytes / sizeof(LangAndCodePage);
            for (size_t i = 0; i < translationCount; ++i)
            {
                const std::wstring product = read_version_string(versionInfo, translations[i].language, translations[i].codePage, L"ProductName");

                if (product.starts_with(POWERTOYS_PRODUCT_NAME_PREFIX))
                {
                    return true;
                }
            }

            Logger::error(L"Installer '{}' version resource doesn't match the PowerToys bootstrapper identity", installerPath);
            return false;
        }

        // .msi identity: the package UpgradeCode (read read-only from the MSI database, so no
        // custom actions run) must be one of PowerToys' UpgradeCodes (shared with MsiUtils.h).
        bool msi_upgrade_code_is_powertoys(const std::wstring& installerPath)
        {
            PMSIHANDLE database;
            UINT result = MsiOpenDatabaseW(installerPath.c_str(), MSIDBOPEN_READONLY, &database);
            if (result != ERROR_SUCCESS)
            {
                Logger::error(L"Couldn't open installer '{}' as an MSI database (error {})", installerPath, result);
                return false;
            }

            PMSIHANDLE view;
            result = MsiDatabaseOpenViewW(database, L"SELECT `Value` FROM `Property` WHERE `Property` = 'UpgradeCode'", &view);
            if (result != ERROR_SUCCESS)
            {
                Logger::error(L"Couldn't query the UpgradeCode of MSI '{}' (error {})", installerPath, result);
                return false;
            }

            result = MsiViewExecute(view, 0);
            if (result != ERROR_SUCCESS)
            {
                Logger::error(L"Couldn't execute the UpgradeCode query for MSI '{}' (error {})", installerPath, result);
                return false;
            }

            PMSIHANDLE record;
            result = MsiViewFetch(view, &record);
            if (result != ERROR_SUCCESS)
            {
                Logger::error(L"MSI '{}' has no UpgradeCode property (error {})", installerPath, result);
                return false;
            }

            wchar_t upgradeCode[64] = {};
            DWORD upgradeCodeLen = ARRAYSIZE(upgradeCode);
            result = MsiRecordGetStringW(record, 1, upgradeCode, &upgradeCodeLen);
            if (result != ERROR_SUCCESS)
            {
                Logger::error(L"Couldn't read the UpgradeCode value of MSI '{}' (error {})", installerPath, result);
                return false;
            }

            if (_wcsicmp(upgradeCode, POWER_TOYS_UPGRADE_CODE) == 0 ||
                _wcsicmp(upgradeCode, POWER_TOYS_UPGRADE_CODE_USER) == 0)
            {
                return true;
            }

            Logger::error(L"MSI '{}' UpgradeCode {} is not a known PowerToys package", installerPath, upgradeCode);
            return false;
        }

        // Confirms the installer is *the PowerToys installer*. Without this, an attacker could supply
        // a different installer or tool for the updater to launch elevated (a confused-deputy elevation).
        bool is_expected_powertoys_installer(const std::wstring& installerPath)
        {
            if (installerPath.ends_with(L".msi"))
            {
                return msi_upgrade_code_is_powertoys(installerPath);
            }
            // Otherwise it is the WiX bootstrapper .exe (matching how Stage 2 launches it).
            return exe_version_info_is_powertoys(installerPath);
        }
    }

    bool verify_installer_trust(const std::wstring& installerPath, void* verifiedFileHandle)
    {
        // The caller keeps verifiedFileHandle open with write/delete sharing denied while this
        // identity check runs. Authenticode/Microsoft-publisher validation is intentionally omitted
        // so self-built unsigned installers can be used.
        (void)verifiedFileHandle;

        // Identity pinning prevents a different installer or tool from being used for a
        // confused-deputy elevation.
        if (!is_expected_powertoys_installer(installerPath))
        {
            Logger::error(L"Installer '{}' is not the PowerToys installer; refusing to run it elevated", installerPath);
            return false;
        }

        return true;
    }
}
