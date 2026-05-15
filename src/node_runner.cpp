/*
 * Copyright (c) 2026, Sifoon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 */

#include "stdafx.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include "node_runner.h"
#include "utilities.h"
#include "logging.h"
#include "resource.h"

NodeRunner::NodeRunner() {
    ZeroMemory(&m_processInfo, sizeof(m_processInfo));
}

NodeRunner::~NodeRunner() {
    Stop();
    Cleanup();
}

bool NodeRunner::Run(const std::wstring& scriptPath, const std::vector<std::wstring>& args) {
    if (!ExtractNode()) {
        return false;
    }

    std::wstring commandLine = L"\"" + m_nodePath + L"\" \"" + scriptPath + L"\"";
    for (const auto& arg : args) {
        commandLine += L" \"" + arg + L"\"";
    }

    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcess(
            m_nodePath.c_str(),
            &commandLine[0],
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &m_processInfo)) {
        my_print(NOT_SENSITIVE, false, _T("Failed to start node process (%d)"), GetLastError());
        return false;
    }

    return true;
}

void NodeRunner::Stop() {
    if (m_processInfo.hProcess != NULL) {
        TerminateProcess(m_processInfo.hProcess, 0);
        CloseHandle(m_processInfo.hProcess);
        CloseHandle(m_processInfo.hThread);
        ZeroMemory(&m_processInfo, sizeof(m_processInfo));
    }
}

bool NodeRunner::ExtractNode() {
    if (!m_nodePath.empty()) {
        return true;
    }

    tstring dataPath;
    if (!GetSifoonDataPath({}, true, dataPath)) {
        my_print(NOT_SENSITIVE, false, _T("Failed to get Sifoon data path"));
        return false;
    }

    m_nodePath = (filesystem::path(dataPath) / "node.exe").wstring();

    if (PathFileExists(m_nodePath.c_str())) {
        return true;
    }

    tstring zipPath = (filesystem::path(dataPath) / "node.zip").wstring();

    if (!ExtractExecutable(IDR_NODE_ZIP, zipPath, true)) {
        my_print(NOT_SENSITIVE, false, _T("Failed to extract node.zip"));
        return false;
    }

    if (!UnzipFile(zipPath, dataPath)) {
        my_print(NOT_SENSITIVE, false, _T("Failed to unzip node.zip"));
        DeleteFile(zipPath.c_str());
        return false;
    }

    DeleteFile(zipPath.c_str());

    if (!PathFileExists(m_nodePath.c_str())) {
        my_print(NOT_SENSITIVE, false, _T("node.exe not found in AppData after unzip"));
        m_nodePath.clear();
        return false;
    }

    return true;
}


void NodeRunner::Cleanup() {
    // We keep node.exe in AppData, so we don't delete it here.
    m_nodePath.clear();
}
