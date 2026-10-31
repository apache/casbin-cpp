#include "casbin/pch.h"

#ifndef FILTERED_FILE_ADAPTER_CPP
#define FILTERED_FILE_ADAPTER_CPP

#include <fstream>

#include "casbin/exception/casbin_adapter_exception.h"
#include "casbin/exception/io_exception.h"
#include "casbin/persist/file_adapter/filtered_file_adapter.h"
#include "casbin/util/util.h"

namespace casbin {

bool FilteredFileAdapter ::filterLine(std::string line, Filter* filter) {
    if (filter == NULL)
        return false;

    std::vector<std::string> p = SplitPolicyLine(line);
    if (p.size() == 0)
        return true;

    std::vector<std::string> filter_slice;
    std::string str = Trim(p[0]);
    if (str == "p")
        filter_slice = filter->P;
    else if (str == "g")
        filter_slice = filter->G;

    return filterWords(p, filter_slice);
}

bool FilteredFileAdapter ::filterWords(std::vector<std::string> line, std::vector<std::string> filter) {
    if (line.size() < filter.size() + 1)
        return true;

    bool skip_line = false;
    for (int i = 0; i < filter.size(); i++) {
        if (filter[i].length() > 0 && Trim(filter[i]) != Trim(line[i + 1])) {
            skip_line = true;
            break;
        }
    }

    return skip_line;
}

void FilteredFileAdapter ::loadFilteredPolicyFile(const std::shared_ptr<Model>& model, Filter* filter, std::function<void(std::string, const std::shared_ptr<Model>&)> handler) {
    std::ifstream out_file;
    try {
        out_file.open(this->file_path);
    } catch (const std::ifstream::failure e) {
        throw IOException("Cannot open file.");
    }

    std::string line;
    while (getline(out_file, line, '\n')) {
        line = Trim(line);
        if (filterLine(line, filter)) {
            continue;
        }

        handler(line, model);
    }

    out_file.close();
}

// NewFilteredAdapter is the constructor for FilteredAdapter.
FilteredFileAdapter ::FilteredFileAdapter(std::string file_path)
    : FileAdapter(file_path) {
    this->filtered = true;
}

// LoadPolicy loads all policy rules from the storage.
void FilteredFileAdapter ::LoadPolicy(const std::shared_ptr<Model>& model) {
    this->filtered = false;
    this->FileAdapter::LoadPolicy(model);
}

// LoadFilteredPolicy loads only policy rules that match the filter.
void FilteredFileAdapter ::LoadFilteredPolicy(const std::shared_ptr<Model>& model, Filter* filter) {
    if (filter == NULL) {
        this->LoadPolicy(model);
    }

    if (this->file_path == "") {
        throw CasbinAdapterException("Invalid file path, file path cannot be empty");
    }

    this->loadFilteredPolicyFile(model, filter, LoadPolicyLine);
    this->filtered = true;
}

// IsFiltered returns true if the loaded policy has been filtered.
bool FilteredFileAdapter ::IsFiltered() {
    return this->filtered;
}

// SavePolicy saves all policy rules to the storage.
void FilteredFileAdapter ::SavePolicy(const std::shared_ptr<Model>& model) {
    if (this->filtered) {
        throw CasbinAdapterException("Cannot save a filtered policy");
    }
    this->SavePolicy(model);
}

} // namespace casbin

#endif // FILTERED_FILE_ADAPTER_CPP
