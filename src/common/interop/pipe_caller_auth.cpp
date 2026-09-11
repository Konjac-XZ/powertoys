#include "pipe_caller_auth.h"

#include <cwctype>
#include <cstring>
#include <map>
#include <mutex>

// Note: the file version is read via the PE resource (kernel32 only), NOT the version.dll APIs, to
// avoid a link-name collision with PowerToys' own static "Version.lib" project that the interop DLL
// references.

namespace interop_auth
{
    namespace
    {
        std::wstring ToLower(std::wstring s)
        {
            for (auto& c : s)
            {
                c = static_cast<wchar_t>(towlower(c));
            }
            return s;
        }

        std::wstring CanonicalizePath(const std::wstring& path)
        {
            // Backup semantics so this works for both files and directories.
            HANDLE h = CreateFileW(path.c_str(),
                                   0,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr,
                                   OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS,
                                   nullptr);
            if (h == INVALID_HANDLE_VALUE)
            {
                // Fail closed: a path we cannot open/canonicalize must not slip past the
                // directory-prefix check as a non-canonical raw path.
                return {};
            }
            wchar_t buf[1024] = {};
            DWORD len = GetFinalPathNameByHandleW(h, buf, ARRAYSIZE(buf), FILE_NAME_NORMALIZED);
            CloseHandle(h);
            if (len == 0 || len >= ARRAYSIZE(buf))
            {
                return {};
            }
            std::wstring result(buf, len);
            if (result.rfind(L"\\\\?\\", 0) == 0)
            {
                result.erase(0, 4);
            }
            return result;
        }

        std::wstring BaseName(const std::wstring& path)
        {
            const auto pos = path.find_last_of(L"\\/");
            return pos == std::wstring::npos ? path : path.substr(pos + 1);
        }

        bool PathIsUnderDirectory(const std::wstring& canonicalFile, const std::wstring& directory)
        {
            if (directory.empty() || canonicalFile.empty())
            {
                return false;
            }
            std::wstring dir = ToLower(CanonicalizePath(directory));
            if (dir.empty())
            {
                // CanonicalizePath failed closed; an empty prefix must not match every path.
                return false;
            }
            if (!dir.empty() && dir.back() != L'\\')
            {
                dir.push_back(L'\\');
            }
            const std::wstring file = ToLower(canonicalFile);
            return file.size() > dir.size() && file.compare(0, dir.size(), dir) == 0;
        }

        bool BasenameAllowed(const std::wstring& canonicalFile, const std::vector<std::wstring>& allowed)
        {
            const std::wstring base = ToLower(BaseName(canonicalFile));
            for (const auto& a : allowed)
            {
                if (ToLower(a) == base)
                {
                    return true;
                }
            }
            return false;
        }

        // --- Per-process verification cache -------------------------------------------------------
        // The cache itself is the header-only interop_auth::VerificationCache, owned per pipe server so
        // verdicts are physically partitioned by policy (key = pid + creation-time). Only the helper to
        // read a process's unforgeable creation-time key lives here.
        unsigned long long ProcessCreationKey(HANDLE process)
        {
            FILETIME create = {}, exit = {}, kernel = {}, user = {};
            if (!GetProcessTimes(process, &create, &exit, &kernel, &user))
            {
                return 0;
            }
            return (static_cast<unsigned long long>(create.dwHighDateTime) << 32) | create.dwLowDateTime;
        }
    }

    unsigned long long GetModuleVersion(const std::wstring& path)
    {
        if (path.empty())
        {
            return 0;
        }
        // Read the fixed file-version from the PE's RT_VERSION resource using kernel32-only APIs
        // (LoadLibraryEx as a data/resource image), avoiding the version.dll import lib.
        HMODULE mod = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
        if (!mod)
        {
            return 0;
        }
        unsigned long long result = 0;
        if (HRSRC res = FindResourceW(mod, MAKEINTRESOURCEW(1 /* VS_VERSION_INFO */), RT_VERSION))
        {
            if (HGLOBAL glob = LoadResource(mod, res))
            {
                const void* locked = LockResource(glob);
                const DWORD size = SizeofResource(mod, res);
                if (locked != nullptr && size >= sizeof(VS_FIXEDFILEINFO))
                {
                    std::vector<BYTE> bytes(size);
                    memcpy(bytes.data(), locked, size);
                    for (size_t i = 0; i + sizeof(VS_FIXEDFILEINFO) <= bytes.size(); i += sizeof(DWORD))
                    {
                        VS_FIXEDFILEINFO ffi{};
                        memcpy(&ffi, &bytes[i], sizeof(ffi));
                        if (ffi.dwSignature == 0xFEEF04BD)
                        {
                            result = (static_cast<unsigned long long>(ffi.dwFileVersionMS) << 32) | ffi.dwFileVersionLS;
                            break;
                        }
                    }
                }
            }
        }
        FreeLibrary(mod);
        return result;
    }

    unsigned long long GetOwnModuleVersion()
    {
        wchar_t self[MAX_PATH * 2] = {};
        const DWORD n = GetModuleFileNameW(nullptr, self, ARRAYSIZE(self));
        if (n == 0 || n >= ARRAYSIZE(self))
        {
            return 0;
        }
        return GetModuleVersion(self);
    }

    AuthResult AuthenticateClient(HANDLE pipe, const CallerPolicy& policy, VerificationCache& cache)
    {
        AuthResult res;
        if (!policy.enabled)
        {
            res.accepted = true;
            return res;
        }

        ULONG pid = 0;
        if (!GetNamedPipeClientProcessId(pipe, &pid))
        {
            res.reasonCode = L"no-client-pid";
            return res;
        }
        res.pid = pid;

        if (policy.expectedClientPid.has_value() && policy.expectedClientPid.value() != pid)
        {
            res.reasonCode = L"pid-mismatch";
            if (policy.logReject)
            {
                policy.logReject(res);
            }
            return res;
        }

        // Hold the process handle for the whole check so the PID cannot be recycled under us.
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
        {
            res.reasonCode = L"open-process-failed";
            if (policy.logReject)
            {
                policy.logReject(res);
            }
            return res;
        }

        const unsigned long long createTime = ProcessCreationKey(process);

        {
            AuthResult cached;
            if (cache.TryGet(pid, createTime, cached))
            {
                cached.pid = pid;
                CloseHandle(process);
                // Do not re-log on a cache hit (dedup across the per-message connections).
                return cached;
            }
        }

        wchar_t imageBuf[MAX_PATH * 2] = {};
        DWORD cch = ARRAYSIZE(imageBuf);
        std::wstring canonical;
        if (QueryFullProcessImageNameW(process, 0, imageBuf, &cch))
        {
            canonical = CanonicalizePath(imageBuf);
        }
        res.imagePath = canonical;

        const wchar_t* reason = L"";
        bool accepted = false;

        if (canonical.empty())
        {
            reason = L"image-path-failed";
        }
        else if (!PathIsUnderDirectory(canonical, policy.expectedDirectory))
        {
            reason = L"bad-directory";
        }
        else if (!BasenameAllowed(canonical, policy.allowedBasenames))
        {
            reason = L"bad-basename";
        }
        else if (policy.expectedVersion != 0 && GetModuleVersion(canonical) != policy.expectedVersion)
        {
            reason = L"version-mismatch";
        }
        else
        {
            accepted = true;
        }

        CloseHandle(process);

        res.accepted = accepted;
        res.reasonCode = reason;

        cache.Put(pid, createTime, res);

        // Required rejection logging (once per process instance, deduped by the cache above).
        if (!accepted && policy.logReject)
        {
            policy.logReject(res);
        }

        return res;
    }
}
