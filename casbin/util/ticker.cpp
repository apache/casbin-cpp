/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "casbin/pch.h"

#ifndef TICKER_CPP
#define TICKER_CPP

#include "casbin/util/ticker.h"

namespace casbin {

Ticker::Ticker(std::function<void()> onTick, std::chrono::duration<int64_t, std::nano> tickInterval)
    : _onTick(onTick)
    , _tickInterval(tickInterval)
    , _running(false) {}

Ticker::~Ticker() {
    stop();
}

void Ticker::start() {
    if (_running) return;
    _running = true;
    _futures1.push_back(std::async(std::launch::async, &Ticker::timer_loop, this));
}

void Ticker::stop() {
    _running = false;
    std::lock_guard<std::mutex> lock(_tickIntervalMutex);
    for (auto&& f : _futures1) {
        f.wait();
    }
    for (auto&& f : _futures2) {
        f.wait();
    }
}

void Ticker::timer_loop() {
    while (_running) {
        {
            std::lock_guard<std::mutex> lock(_tickIntervalMutex);
            _futures2.push_back(std::async(std::launch::async, _onTick));
            std::this_thread::sleep_for(_tickInterval);
        }
    }
}

} // namespace casbin

#endif // TICKER_CPP
