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

#pragma once

#include <unordered_set>
#include <optional>

template<>
struct std::hash<std::vector<std::string>> {
       auto operator()(const std::vector<std::string>& rules) const -> size_t {
               size_t result = 0;
               for(const auto& rule : rules)
                       result ^= std::hash<std::string>{}(rule);
               return result;
       }
};

using PolicyValues = std::vector<std::string>;
using PoliciesVector = std::vector<PolicyValues>;
using PoliciesHashset = std::unordered_set<PolicyValues>;

class PoliciesValues final {
public:
using PolicyValues = std::vector<std::string>;
using PoliciesVector = std::vector<PolicyValues>;
using PoliciesHashset = std::unordered_set<PolicyValues>;
private:
    std::optional<PoliciesVector> opt_base_vector;
    std::optional<PoliciesHashset> opt_base_hashset;

    PoliciesValues(PoliciesVector&& base_collection);
    PoliciesValues(PoliciesHashset&& base_collection);
public:
    PoliciesValues(const std::initializer_list<PolicyValues>& list={});
    PoliciesValues(size_t capacity);
    static PoliciesValues createWithVector(const std::initializer_list<PolicyValues>& list={});
    static PoliciesValues createWithHashset(const std::initializer_list<PolicyValues>& list={});

    size_t size() const;
    bool empty() const;
    bool is_hash() const;
    void emplace(const PolicyValues& element);
    class iterator final : std::input_iterator_tag {
        private:
            bool is_vector_iterator;
            mutable PoliciesVector::iterator opt_vector_iterator;
            mutable PoliciesHashset::iterator opt_hashset_iterator;
            iterator(const PoliciesVector::iterator& base_iterator_);
            iterator(const PoliciesHashset::iterator& base_iterator_);
            friend class PoliciesValues;
        public:
            using iterator_category = std::input_iterator_tag;
            using difference_type=std::ptrdiff_t;
            using value_type=PolicyValues;
            using pointer = value_type*;
            using reference = value_type&;
            PolicyValues& operator*() const;
            iterator operator++();
            bool operator!=(const iterator& other) const;
    };

    iterator begin();
    iterator end();

    class const_iterator final : std::input_iterator_tag {
        private:
            bool is_vector_iterator;
            mutable PoliciesVector::const_iterator opt_vector_iterator;
            mutable PoliciesHashset::const_iterator opt_hashset_iterator;
            const_iterator(const PoliciesVector::const_iterator& base_iterator_);
            const_iterator(const PoliciesHashset::const_iterator& base_iterator_);
            friend class PoliciesValues;
        public:
            using iterator_category = std::input_iterator_tag;
            using difference_type = std::ptrdiff_t;
            using value_type = const PolicyValues;
            using pointer = value_type*;
            using reference = value_type&;
            const PolicyValues& operator*() const;
            const_iterator operator++();
            bool operator!=(const const_iterator& other) const;
    };

    const_iterator begin() const;
    const_iterator end() const;

    iterator find(const PolicyValues&);
    void clear();

    void erase(const iterator&);
};
