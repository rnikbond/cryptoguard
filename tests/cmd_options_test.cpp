#include "cmd_options.h"
#include <boost/scope_exit.hpp>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <vector>

/**
 * @brief Проверка всех необходимых аргументов - аргументы переданы корректно.
 */
TEST(ProgramOptions, Args_OK) {

    std::string filePath = "input_test.txt";
    std::vector<std::string> arguments = {"path_to_bin", "--command", "checksum", "-i", filePath};

    std::vector<char *> argv;
    for (std::string &arg : arguments) {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }

    //: Временно создаем файл с входными данными
    if (!std::filesystem::exists(filePath)) {
        std::ofstream file(filePath);
    }
    BOOST_SCOPE_EXIT(filePath) { std::filesystem::remove(filePath); }
    BOOST_SCOPE_EXIT_END

    CryptoGuard::ProgramOptions options;
    ASSERT_NO_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM, options.GetCommand());
    EXPECT_EQ(filePath, options.GetInputFile());
}

/**
 * @brief Проверка аргумента "input" - указан несуществующий файл.
 */
TEST(ProgramOptions, InputFile_NotExists) {

    std::string filePath = "input_test_no_exists.txt";
    std::vector<std::string> arguments = {"path_to_bin", "--command", "checksum", "-i", filePath};

    std::vector<char *> argv;
    for (std::string &arg : arguments) {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }

    CryptoGuard::ProgramOptions options;
    EXPECT_ANY_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
}

/**
 * @brief Проверка аргумента "input" - аргумент не указан
 */
TEST(ProgramOptions, InputFile_NotSetted) {

    std::vector<std::string> arguments = {"path_to_bin", "--command", "checksum"};

    std::vector<char *> argv;
    for (std::string &arg : arguments) {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }

    CryptoGuard::ProgramOptions options;
    EXPECT_ANY_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
}

/**
 * @brief Проверка аргумента "command" - аргумент не указан.
 */
TEST(ProgramOptions, Command_NotSetted) {

    std::string filePath = "input_test.txt";
    std::vector<std::string> arguments = {"path_to_bin", "-i", filePath};

    std::vector<char *> argv;
    for (std::string &arg : arguments) {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }

    //: Временно создаем файл с входными данными
    if (!std::filesystem::exists(filePath)) {
        std::ofstream file(filePath);
    }
    BOOST_SCOPE_EXIT(filePath) { std::filesystem::remove(filePath); }
    BOOST_SCOPE_EXIT_END

    CryptoGuard::ProgramOptions options;
    EXPECT_ANY_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
}

/**
 * @brief Проверка аргумента "command" - передан некорректный.
 */
TEST(ProgramOptions, Command_Unknown) {

    std::string filePath = "input_test.txt";
    std::vector<std::string> arguments = {"path_to_bin", "--command", "unknown", "-i", filePath};

    std::vector<char *> argv;
    for (std::string &arg : arguments) {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }

    //: Временно создаем файл с входными данными
    if (!std::filesystem::exists(filePath)) {
        std::ofstream file(filePath);
    }
    BOOST_SCOPE_EXIT(filePath) { std::filesystem::remove(filePath); }
    BOOST_SCOPE_EXIT_END

    CryptoGuard::ProgramOptions options;
    EXPECT_ANY_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
}

/**
 * @brief Проверка аргумента "command" - указан только флаг, без значения.
 */
TEST(ProgramOptions, Command_OnlyFlag) {

    std::string filePath = "input_test.txt";
    std::vector<std::string> arguments = {"path_to_bin", "--command", "-i", filePath};

    std::vector<char *> argv;
    for (std::string &arg : arguments) {
        argv.push_back(const_cast<char *>(arg.c_str()));
    }

    //: Временно создаем файл с входными данными
    if (!std::filesystem::exists(filePath)) {
        std::ofstream file(filePath);
    }
    BOOST_SCOPE_EXIT(filePath) { std::filesystem::remove(filePath); }
    BOOST_SCOPE_EXIT_END

    CryptoGuard::ProgramOptions options;
    EXPECT_ANY_THROW(options.Parse(static_cast<int>(argv.size()), argv.data()));
}