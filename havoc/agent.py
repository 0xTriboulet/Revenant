from asyncio import Task
import base64
import json
import struct
import uuid
import random
import string
from struct import pack, calcsize

from black import out
from itsdangerous import base64_encode


def build_request(head_type, body: dict) -> dict:
    return {
        "Head": {
            "Type": head_type
        },
        "Body": body
    }


class Packer:
    buffer: bytes = b''
    length: int = 0

    def get_buffer( self ) -> bytes:
        return pack( "<L", self.length ) + self.buffer

    def add_int( self, data ) -> None:

        self.buffer += pack( "<i", data )
        self.length += 4

        return

    def add_data( self, data: str ) -> None:

        if isinstance( data, str ):
            data = data.encode( "utf-8" )

        fmt = "<L{}s".format( len( data ) + 1 )

        self.buffer += pack( fmt, len( data ) + 1, data )
        self.length += calcsize( fmt )

    def dump( self ) -> None:

        print( f"[*] Buffer: [{ self.length }] [{ self.get_buffer() }]" )

        return


class Parser:
    buffer: bytes = b''
    length: int = 0

    def __init__( self, buffer, length ):

        self.buffer = buffer
        self.length = length

        return

    def parse_int( self ) -> int:

        val = struct.unpack( ">i", self.buffer[ :4 ] )
        self.buffer = self.buffer[ 4: ]

        return val[ 0 ]

    def parse_bytes( self ) -> bytes:

        length      = self.parse_int()

        buf         = self.buffer[ :length ]
        self.buffer = self.buffer[ length: ]

        return buf

    def parse_pad( self, length: int ) -> bytes:

        buf         = self.buffer[ :length ]
        self.buffer = self.buffer[ length: ]

        return buf

    def parse_str( self ) -> str:
        return self.parse_bytes().decode( 'utf-8' )

class CommandParam:
    Name: str
    IsFilePath: bool
    IsOptional: bool

    def __init__( self, name: str, is_file_path: bool, is_optional: bool ):

        self.Name = name
        self.IsFilePath = is_file_path
        self.IsOptional = is_optional

        return


class Command:
    Name: str
    Description: str
    Help: str
    NeedAdmin: bool
    Mitr: list[ str ]
    Params: list[ CommandParam ]
    CommandId: int

    def job_generate( self, arguments: dict ) -> bytes:
        pass

    def get_dict( self ) -> dict:
        return {
            "Name": self.Name,
            "Author": self.Author,  # todo: remove this
            "Description": self.Description,
            "Help": self.Help,
            "NeedAdmin": self.NeedAdmin,
            "Mitr": self.Mitr,
        }


class AgentType:
    Name: str
    Author: str
    Version: str
    MagicValue: int
    Description: str
    Arch = list[ str ]
    Formats = list[ dict ]
    Commands: list[ Command ]
    BuildingConfig = dict

    _Service_instance = None

    _current_data: dict = {}

    def task_prepare( self, arguments: dict ) -> bytes:

        for cmd in self.Commands:
            if arguments[ "Command" ] == cmd.Name:
                return cmd.job_generate( arguments )
                
    def generate( self, config: dict ) -> None:
        pass

    def download_file( self, agent_id: str, file_name: str, size: int, content: str ) -> None:
        ContentB64 = base64.b64encode( content.encode( 'utf-8' ) ).decode( 'utf-8' )

        self._Service_instance.Socket.send( 
            json.dumps( 
                {
                    "Head": {
                        "Type": "Agent"
                    },
                    "Body": {
                        "Type"    : "AgentOutput",
                        "AgentID" : agent_id,
                        "Callback" : {
                            "MiscType" : "download",
                            "FileName" : file_name,
                            "Size"     : size,
                            "Content"  : ContentB64
                        }
                    }
                }
            ) 
        )

        return

    def console_message( self, agent_id: str, type: str, message: str, output: str ) -> None:
        
        self._Service_instance.Socket.send(
            json.dumps(
                {
                    "Head": {
                        "Type": "Agent"
                    },
                    "Body": {
                        "Type"    : "AgentOutput",
                        "AgentID" : agent_id,
                        "Callback" : {
                            "Type"   : type,
                            "Message": message,
                            "Output" : output
                        }
                    }
                }
            )
        )

        return

    def get_task_queue( self, AgentInfo: dict ) -> bytes:
        
        RandID : str   = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(6))
        Tasks  : bytes = b''

        self._Service_instance.Socket.send(
            json.dumps(
                {
                    "Head": {
                        "Type": "Agent"
                    },
                    "Body": {
                        "Type" :  "AgentTask",
                        "Agent":  AgentInfo, 
                        "Task":   "Get",
                        "RandID": RandID
                    }
                }
            )
        )

        while ( True ):
            if RandID in self._current_data:
                Tasks = self._current_data[ RandID ]
                del self._current_data[ RandID ]
                break
            else:
                continue

        return Tasks

    def register( self, agent_header: dict, register_info: dict ):
        self._Service_instance.Socket.send(
            json.dumps(
                {
                    "Head": {
                        "Type": "Agent"
                    },
                    "Body": {
                        "Type": "AgentRegister",
                        "AgentHeader" : agent_header,
                        "RegisterInfo": register_info
                    }
                }
            )
        )

        return

    def response( self, response: dict ) -> bytes:
        pass

    def builder_send_message(self, client_id: str, msg_type: str, message: str):

        self._Service_instance.Socket.send(
            json.dumps(
                {
                    "Head": {
                        "Type": "Agent"
                    },
                    "Body": {
                        "ClientID": client_id,
                        "Type": "AgentBuild",
                        "Message": {
                            "Type": msg_type,
                            "Message": message
                        }
                    }
                }
            )
        )

        return

    def builder_send_payload( self, client_id: str, filename: str, payload: bytes ):

        self._Service_instance.Socket.send(
            json.dumps(
                build_request("Agent", {
                    "ClientID": client_id,
                    "Type": "AgentBuild",
                    "Message": {
                        "FileName": filename,
                        "Payload": base64.b64encode(payload).decode('utf-8')
                    }
                })
            )
        )

        return

    def get_dict( self ) -> dict:
        AgentCommands: list[ dict ] = []

        for command in self.Commands:
            command_params: list[dict] = []

            for param in command.Params:
                command_params.append( {
                    "Name": param.Name,
                    "IsFilePath": param.IsFilePath,
                    "IsOptional": param.IsOptional,
                } )

            AgentCommands.append( {
                "Name": command.Name,
                "Description": command.Description,
                "Help": command.Help,
                "NeedAdmin": command.NeedAdmin,
                "Mitr": command.Mitr,
                "Params": command_params
            } )

        return {
            "Name": self.Name,
            "MagicValue": hex( self.MagicValue ),
            "BuildingConfig": self.BuildingConfig,
            "Arch": self.Arch,
            "Formats": self.Formats,
            "Author": self.Author,
            "Description": self.Description,
            "Commands": AgentCommands
        }
