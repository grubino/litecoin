#ifndef JSON_IO_HELPERS_H_
#define JSON_IO_HELPERS_H_

#include <string>
#include <stdexcept>
#include <ciere/json/value.hpp>
#include <ciere/json/io.hpp>

extern std::string write_string(const ciere::json::value& v, bool _);
extern ciere::json::value read_json(const std::string& filename);

#endif
