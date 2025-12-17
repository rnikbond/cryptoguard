#include "cmd_options.h"
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <filesystem>
#include <iostream>
#include <ranges>
#include <stdexcept>

namespace fs = std::filesystem;
namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

    // Собираем доступные команды
    std::string allowedCommands;
    for (const auto &cmd : commandMapping_ | std::views::keys) {
        if (!allowedCommands.empty()) {
            allowedCommands += ", ";
        }
        allowedCommands += cmd;
    }

    desc_.add_options()("help,h", "Available commands");
    desc_.add_options()("command,c",
                        po::value<std::string>()
                            ->notifier([this](std::string value) {
                                auto it = commandMapping_.find(value);
                                if (it != commandMapping_.end()) {
                                    command_ = it->second;
                                } else {
                                    throw std::runtime_error("unknown command");
                                }
                            })
                            ->required(),
                        allowedCommands.data());
    desc_.add_options()("input,i",
                        po::value<std::string>()
                            ->notifier([this](std::string path) {
                                if (fs::is_regular_file(path)) {
                                    this->inputFile_ = path;
                                } else {
                                    throw std::runtime_error("input file does not exists");
                                }
                            })
                            ->required(),
                        "input file data");
    desc_.add_options()("output,o", po::value<std::string>(&outputFile_)->default_value("result.out"),
                        "output file for result");
    desc_.add_options()("password,p", po::value<std::string>(&password_)->composing(),
                        "password for encrypt and decrypt");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {

    po::variables_map argsMap;
    po::parsed_options argsParsed = po::parse_command_line(argc, argv, desc_);
    po::store(argsParsed, argsMap);

    if (argsMap.count("help")) {
        std::cout << "--- HELP MESSAGE ---" << std::endl;
        std::cout << desc_ << std::endl;
        exit(0);
    }

    po::notify(argsMap);
}

}  // namespace CryptoGuard
