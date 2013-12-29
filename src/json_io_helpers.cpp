#include "json_io_helpers.h"

#include <boost/spirit/include/classic_file_iterator.hpp>

std::string write_string(const ciere::json::value& v, bool _ = false) {
  std::stringstream ss;
  ss << v;
  return ss.str();
}

ciere::json::value read_json(const std::string& filename) {
  boost::spirit::classic::file_iterator<char> fit(filename.c_str());
  return ciere::json::construct(fit, fit.make_end());
}
