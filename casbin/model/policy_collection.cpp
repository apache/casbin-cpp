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

#include "casbin/model/policy_collection.hpp"


PoliciesValues::PoliciesValues(PoliciesVector&& base_collection)
    : opt_base_vector(base_collection), opt_base_hashset({}) {}

PoliciesValues::PoliciesValues(PoliciesHashset&& base_collection)
    : opt_base_vector({}), opt_base_hashset(base_collection) {}

PoliciesValues::PoliciesValues(const std::initializer_list<PolicyValues>& list) 
	: opt_base_vector(list), opt_base_hashset({}) {}

PoliciesValues::PoliciesValues(size_t capacity)
    : opt_base_vector(PoliciesVector()), opt_base_hashset({}) {
    opt_base_vector->reserve(capacity);
}

PoliciesValues PoliciesValues::createWithVector(const std::initializer_list<PolicyValues>& list) {
    PoliciesVector vec(list);
    return PoliciesValues(std::move(vec));
}

PoliciesValues PoliciesValues::createWithHashset(const std::initializer_list<PolicyValues>& list) {
    PoliciesHashset hashset(list);
    return PoliciesValues(std::move(hashset));
}

size_t PoliciesValues::size() const {
    if (opt_base_vector.has_value())
    	return opt_base_vector->size();
    return opt_base_hashset->size();
}

bool PoliciesValues::empty() const {
    if(opt_base_vector.has_value())
        return opt_base_vector->empty();
    return opt_base_hashset->empty();
}

bool PoliciesValues::is_hash() const {
    return opt_base_hashset.has_value();
}

void PoliciesValues::emplace(const PolicyValues& element) {
    if (opt_base_vector.has_value()) 
        opt_base_vector->push_back(element);
    else
        opt_base_hashset->emplace(element);
}

PoliciesValues::iterator::iterator(const PoliciesVector::iterator& base_iterator_)
    : opt_vector_iterator(base_iterator_), is_vector_iterator(true) {}

PoliciesValues::iterator::iterator(const PoliciesHashset::iterator& base_iterator_)
    : opt_hashset_iterator(base_iterator_), is_vector_iterator(false) {}

PolicyValues& PoliciesValues::iterator::operator*() const {
     if ( is_vector_iterator )
         return *opt_vector_iterator;
     return const_cast<PolicyValues&>(*opt_hashset_iterator);
}

PoliciesValues::iterator  PoliciesValues::iterator::operator++() { 
     if ( is_vector_iterator )
         opt_vector_iterator++;
     else
         opt_hashset_iterator++;
     return *this;
}

bool PoliciesValues::iterator::operator!=(const PoliciesValues::iterator& other) const {
     return opt_vector_iterator != other.opt_vector_iterator || opt_hashset_iterator != other.opt_hashset_iterator;
}

PoliciesValues::iterator PoliciesValues::begin() { 
    if (opt_base_vector.has_value())
        return iterator(opt_base_vector->begin());
    return iterator(opt_base_hashset->begin());
}

PoliciesValues::iterator PoliciesValues::end() { 
    if (opt_base_vector.has_value())
        return iterator(opt_base_vector->end());
    return iterator(opt_base_hashset->end());
}

PoliciesValues::iterator PoliciesValues::find(const PolicyValues& values) {
    if (opt_base_vector.has_value()) 
        return iterator(std::find(opt_base_vector->begin(), opt_base_vector->end(), values));
    return iterator(opt_base_hashset->find(values));
}

void PoliciesValues::clear() {
    if (opt_base_vector.has_value())
        opt_base_vector->clear();
    else
        opt_base_hashset->clear();
}

void PoliciesValues::erase(const iterator& it) {
    if (opt_base_vector.has_value())
        opt_base_vector->erase(it.opt_vector_iterator);
    else
        opt_base_hashset->erase(it.opt_hashset_iterator);
}

PoliciesValues::const_iterator::const_iterator(const PoliciesVector::const_iterator& base_iterator_)
    : opt_vector_iterator(base_iterator_), is_vector_iterator(true) {

}

PoliciesValues::const_iterator::const_iterator(const PoliciesHashset::const_iterator& base_iterator_)
    : opt_hashset_iterator(base_iterator_), is_vector_iterator(false) {
}

const PolicyValues& PoliciesValues::const_iterator::operator*() const {
     if ( is_vector_iterator )
         return *opt_vector_iterator;
     return *opt_hashset_iterator;
}

PoliciesValues::const_iterator PoliciesValues::const_iterator::operator++() {
     if ( is_vector_iterator )
         opt_vector_iterator++;
     else
         opt_hashset_iterator++;
     return *this;
}

bool PoliciesValues::const_iterator::operator!=(const const_iterator& other) const {
     return opt_vector_iterator != other.opt_vector_iterator || opt_hashset_iterator != other.opt_hashset_iterator;
}


PoliciesValues::const_iterator PoliciesValues::begin() const {
    if (opt_base_vector.has_value())
        return const_iterator(opt_base_vector->cbegin());
    return const_iterator(opt_base_hashset->cbegin());
}

PoliciesValues::const_iterator PoliciesValues::end() const {
    if (opt_base_vector.has_value())
        return const_iterator(opt_base_vector->cend());
    return const_iterator(opt_base_hashset->cend());
}
