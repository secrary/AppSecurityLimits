import lief
import sys
import os
import json

def main():
    if (len(sys.argv) == 2):
        file_name = sys.argv[1]
        if os.path.isdir(file_name):
            return
        pe_binary = lief.parse(file_name)
        pe_sections = pe_binary.sections

        magic_string = ".appseclimits_"
        for section in pe_sections:
            if section.name == ".appsec" and section.size > len(magic_string):
                magic_list = section.content[:14]
                magic = ''.join(chr(x) for x in magic_list)
                if (magic != magic_string):
                    continue
                section_data = section.content[14:]
                json_config_data = ''.join(chr(x) for x in section_data)
                json_content = json.loads(json_config_data)
                if json_content["remote_process_access"] == False:
                    print("Allow remote process access: WriteProcessMemory, etc")
                # ...

if __name__ == "__main__":
    main()
        