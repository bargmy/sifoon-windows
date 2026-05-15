/*
 * Copyright (c) 2020, Sifoon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "stdafx.h"
#include <shlwapi.h>
#pragma comment(lib,"shlwapi.lib")

#include "logging.h"
#include "coretransport.h"
#include "sessioninfo.h"
#include "psiclient.h"
#include "utilities.h"
#include "systemproxysettings.h"
#include "config.h"
#include "diagnostic_info.h"
#include "embeddedvalues.h"
#include "utilities.h"
#include "authenticated_data_package.h"
#include "sifoon_tunnel_core_utilities.h"


#define UPGRADE_EXE_NAME                     _T("sifoon3.exe.upgrade")

string GetUpstreamProxyAddress()
{
    // Note: only HTTP proxies and basic auth are currently supported

    if (Settings::SkipUpstreamProxy())
    {
        // Don't use an upstream proxy of any kind.
        return "";
    }

    string upstreamProxyAddress = Settings::UpstreamProxyFullHostname();
    if (upstreamProxyAddress.empty())
    {
        // There's no user-set upstream proxy, so use the native default proxy
        // (that is, the one that was set before we tried to connect).
        auto proxyConfig = GetNativeDefaultProxyConfig();
        if (proxyConfig.HTTPEnabled())
        {
            upstreamProxyAddress = WStringToUTF8(proxyConfig.HTTPHostPortScheme());
        }
    }

    return upstreamProxyAddress;
}

bool WriteParameterFiles(const WriteParameterFilesIn& in, WriteParameterFilesOut& out)
{
    tstring dataStoreDirectory;
    if (!GetSifoonDataPath({}, true, dataStoreDirectory)) {
        my_print(NOT_SENSITIVE, false, _T("%s - GetSifoonDataPath failed for dataStoreDirectory (%d)"), __TFUNCTION__, GetLastError());
        return false;
    }

    tstring shortDataStoreDirectory;
    if (!GetShortPathName(dataStoreDirectory, shortDataStoreDirectory))
    {
        my_print(NOT_SENSITIVE, false, _T("%s - GetShortPathName failed (%d)"), __TFUNCTION__, GetLastError());
        return false;
    }

    Json::Value config;
    config["script_id"] = Settings::GoogleScriptId();
    config["auth_key"] = Settings::GoogleAuthKey();
    config["front_domain"] = Settings::GoogleFrontDomain().empty() ? "www.google.com" : Settings::GoogleFrontDomain();
    config["google_ip"] = Settings::GoogleIp().empty() ? "216.239.38.120" : Settings::GoogleIp();
    config["listen_port"] = Settings::LocalHttpProxyPort() == 0 ? 8087 : Settings::LocalHttpProxyPort();

    string upstreamProxyAddress = GetUpstreamProxyAddress();
    if (!upstreamProxyAddress.empty()) {
        config["UpstreamProxyURL"] = upstreamProxyAddress;
    }

    ostringstream configDataStream;
    Json::FastWriter jsonWriter;
    configDataStream << jsonWriter.write(config);

    auto configPath = filesystem::path(dataStoreDirectory);
    configPath.append(in.configFilename);
    out.configFilePath = configPath;

    if (!WriteFile(out.configFilePath, configDataStream.str()))
    {
        my_print(NOT_SENSITIVE, false, _T("%s - write config file failed (%d)"), __TFUNCTION__, GetLastError());
        return false;
    }

    if (!in.requestingUrlProxyWithoutTunnel)
    {
        auto serverListPath = filesystem::path(dataStoreDirectory)
            .append(LOCAL_SETTINGS_APPDATA_SERVER_LIST_FILENAME);
        out.serverListFilename = serverListPath;
    }

    return true;
}
