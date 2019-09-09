#include <Windows.h>

#include <fstream>
#include <memory>
#include <filesystem>
namespace fs = std::filesystem;

#pragma warning(disable : 4146)
#include <LIEF/LIEF.hpp>
#include <nlohmann/json.hpp>

bool add_section_to_executable(const std::string& file_path, const std::string& new_path,
                               const std::vector<uint8_t>& data)
{
	std::unique_ptr<LIEF::PE::Binary> pe_binary = nullptr;
	try
	{
		pe_binary = {LIEF::PE::Parser::parse(file_path)};
	}
	catch (...)
	{
		printf("[Exception] Failed to parse a file: %s\n", file_path.c_str());
		return false;
	}
	if (pe_binary == nullptr)
	{
		printf("[nullptr] Failed to parse a file: %s\n", file_path.c_str());
		return false;
	}


	LIEF::PE::Section new_section{};
	new_section.name(".appsec");
	new_section.content(data);

	pe_binary.get()->add_section(new_section, LIEF::PE::PE_SECTION_TYPES::RESOURCE);
	pe_binary.get()->write(new_path);

	return true;
}

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		printf("Usage: appsecuritylimits.exe executable_path json_config_path\n\n");
		return -1;
	}
	const std::string original_path(argv[1]);
	if (!fs::exists(original_path) || !original_path.ends_with(".exe"))
	{
		printf("Input file path is invalid: %s\n", original_path.c_str());
		return -1;
	}
	const std::string new_path = original_path + ".appseclimit.exe";
	const std::string json_file(argv[2]);

	if (!fs::exists(json_file) || fs::is_empty(json_file))
	{
		printf("Failed to parse json file: %s\n", json_file.c_str());
		return -1;
	}
	std::ifstream input_file(json_file);
	nlohmann::json app_sec_json;
	input_file >> app_sec_json;
	input_file.close();

	// child_processes field is mandatory
	if (app_sec_json["child_processes"].is_null())
	{
		printf("invalid JSON file: %s\nchild_processes field is mandatory\n\n", json_file.c_str());
		return -1;
	}

	const std::string magic = ".appseclimits_";
	const size_t vector_size = magic.length() + app_sec_json.dump().length();
	std::vector<uint8_t> data(vector_size, 0);

	const std::string full_string = magic + app_sec_json.dump();
	std::transform(full_string.begin(), full_string.end(), data.begin(),
	               [](char c) { return uint8_t(c); });

	add_section_to_executable(original_path, new_path, data);

	return 0;
}
