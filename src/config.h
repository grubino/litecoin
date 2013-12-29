#ifndef CONFIG_H_
#define CONFIG_H_

#include <boost/program_options.hpp>

extern boost::program_options::variables_map user_options;
extern boost::program_options::options_description gen_opts;
extern boost::program_options::options_description config_opts;
extern boost::program_options::options_description opts;
extern boost::program_options::positional_options_description pos_opts;

extern void config_init(int argc, char** argv);

#endif
