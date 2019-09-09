#include <Windows.h>

#include <memory>
#include <filesystem>
namespace fs = std::filesystem;

#pragma warning(disable : 4146)
#include <LIEF/LIEF.hpp>

bool add_section_to_executable(const std::string& file_path, const std::string& new_path, const std::vector<uint8_t>& data)
{

	std::unique_ptr<LIEF::PE::Binary> pe_binary = nullptr;
	try {
		pe_binary = {LIEF::PE::Parser::parse(file_path)};
	}
	catch (...) {
		printf("[Exception] Failed to parse a file: %s\n", file_path.c_str());
		return false;
	}
	if (pe_binary == nullptr) {
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

int main()
{
    const std::string original_path = R"(C:\Users\XXX\Downloads\Desktops.exe)";
	const std::string new_path = original_path + ".new.exe";

	std::vector<uint8_t> data(4096, 0);

	add_section_to_executable(original_path, new_path, data);

	return 0;
}


