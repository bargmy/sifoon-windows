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

#pragma once

#include "stdafx.h"
#include <string>
#include <vector>

class NodeRunner {
public:
    NodeRunner();
    ~NodeRunner();

    /**
     * Extracts node.exe and runs it with the specified script and arguments.
     * @param scriptPath The path to the JavaScript file to run.
     * @param args Additional arguments to pass to node.
     * @return true if successful, false otherwise.
     */
    bool Run(const std::wstring& scriptPath, const std::vector<std::wstring>& args);

    /**
     * Stops the running node process.
     */
    void Stop();

private:
    bool ExtractNode();
    void Cleanup();

    std::wstring m_nodePath;
    PROCESS_INFORMATION m_processInfo;
};
