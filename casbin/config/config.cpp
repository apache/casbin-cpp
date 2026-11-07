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

#ifndef CONFIG_CPP
#define CONFIG_CPP

#include "casbin/config/config.h"
#include "casbin/exception/illegal_argument_exception.h"
#include "casbin/exception/io_exception.h"
#include "casbin/util/util.h"

namespace casbin {

const std::string Config::DEFAULT_SECTION = "default";
const std::string Config::DEFAULT_COMMENT = "#";
const std::string Config::DEFAULT_COMMENT_SEM = ";";
std::mutex Config::mtx_lock;

/**
 * addConfig adds a new section->key:value to the configuration.
 */
bool Config::AddConfig(std::string section, const std::string& option, const std::string& value) {
    if (!section.compare(""))
        section = DEFAULT_SECTION;
    bool ok = data[section].find(option) != data[section].end();
    data[section][option] = value;
    return !ok;
}

void Config::Parse(const std::string& f_name) {
    mtx_lock.lock();
    std::ifstream infile;
    try {
        infile.open(f_name);
    } catch (const std::ifstream::failure e) {
        mtx_lock.unlock();
        throw IOException("Cannot open file.");
    }
    ParseBuffer(&infile);
    mtx_lock.unlock();
    infile.close();
}

void Config::ParseBuffer(std::istream* buf) {
    std::string section = "";
    int line_num = 0;
    std::string line;
    while (true) {
        line_num++;
        if (getline(*buf, line, '\n')) {
            if (!line.compare(""))
                continue;
        } else
            break;
        line = Trim(line);
        if (line.find(DEFAULT_COMMENT) == 0)
            continue;
        else if (line.find(DEFAULT_COMMENT_SEM) == 0)
            continue;
        else if (line.find("[") == 0 && EndsWith(line, "]"))
            section = line.substr(1, line.length() - 2);
        else {
            std::vector<std::string> option_val = Split(line, "=", 2);
            if (option_val.size() != 2) {
                std::string error = "parse the content error : line " + std::to_string(line_num)  + " , " + option_val[0] + " = ?";
                throw IllegalArgumentException(error);
            }
            std::string option = Trim(option_val[0]);
            std::string value = Trim(option_val[1]);
            AddConfig(section, option, value);
        }
    }
}

/**
 * newConfig create an empty configuration representation from file.
 *
 * @param confName the path of the model file.
 * @return the constructor of Config.
 */
std::shared_ptr<Config> Config::NewConfig(const std::string& conf_name) {
    std::shared_ptr<Config> c = std::make_shared<Config>();
    c->Parse(conf_name);
    return c;
}

/**
 * newConfigFromText create an empty configuration representation from text.
 *
 * @param text the model text.
 * @return the constructor of Config.
 */
std::shared_ptr<Config> Config::NewConfigFromText(const std::string& text) {
    std::shared_ptr<Config> c = std::make_shared<Config>();
    std::stringstream stream(text);
    c->ParseBuffer(&stream);
    return c;
}

Config::Config() {
}

Config::Config(const std::string& conf_name) {
    this->Parse(conf_name);
}

bool Config::GetBool(std::string_view key) {
    return Get(key).compare("true") == 0;
}

int Config::GetInt(std::string_view key) {
    return atoi(Get(key).c_str());
}

float Config::GetFloat(std::string_view key) {
    return float(atof(Get(key).c_str()));
}

std::string Config::GetString(std::string_view key) {
    return Get(key);
}

std::vector<std::string> Config::GetStrings(std::string_view key) {
    std::string v = Get(key);

    if (!v.compare(""))
        return {};

    return Split(v, ",");
}

void Config::Set(std::string_view key, const std::string& value) {
    mtx_lock.lock();
    if (key.length() == 0) {
        mtx_lock.unlock();
        throw IllegalArgumentException("key is empty");
    }

    std::string section = "";
    std::string option;

    std::vector<std::string> keys = Split(std::string(key), "::");
    if (keys.size() >= 2) {
        section = keys[0];
        option = keys[1];
    } else
        option = keys[0];

    AddConfig(section, option, value);
    mtx_lock.unlock();
}

std::string Config::Get(std::string_view key) {
    std::string section;
    std::string option;

    std::vector<std::string> keys = Split(std::string(key), "::");
    if (keys.size() >= 2) {
        section = keys[0];
        option = keys[1];
    } else {
        section = DEFAULT_SECTION;
        option = keys[0];
    }
    bool ok = data.find(section) != data.end() && data[section].find(option) != data[section].end();
    if (ok)
        return data[section][option];
    return "";
}

} // namespace casbin

#endif // CONFIG_CPP
