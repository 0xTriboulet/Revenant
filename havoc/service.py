import base64
from cgi import print_form

from havoc.agent import AgentType
from havoc.externalc2 import ExternalC2
from threading import Thread

import ssl
import websocket
import json


def build_request(head_type, body: dict) -> dict:
    return {
        "Head": {
            "Type": head_type
        },
        "Body": body
    }


class HavocService:

    Socket: websocket.WebSocketApp = None
    Teamserver: str = None
    Endpoint: str = None
    Password: str = None
    Connected: bool = False
    RegisteredAgent: AgentType = None

    def __init__(self, endpoint: str, password: str):

        if len(endpoint) > 0:
            self.Endpoint = endpoint
        else:
            print("[!] endpoint not specified.")

        if len(password) > 0:
            self.Password = password
        else:
            print("[!] password not specified.")

        self.Socket = websocket.WebSocketApp(
            endpoint,
            on_error=self.__ws_on_error,
            on_message=self.__ws_on_message,
            on_open=self.__ws_on_open
        )

        Thread(target=self.Socket.run_forever, kwargs={"sslopt": {"cert_reqs": ssl.CERT_NONE}}).start()


        while True:
            if self.Connected:
                break

        return

    def __ws_on_error(self, wsapp, error):
        print("[-] Websocket error:", error)

    def __ws_on_open(self, socket):
        print("[*] teamserver socket opened")

        request = json.dumps(
            build_request("Register", {
                "Password": self.Password
            }),
            sort_keys=True
        )

        socket.send( request )
        return

    def __ws_on_message( self, ws, data ):
        print( "[*] New Message" )

        data = json.loads( data )

        t = Thread(target=self.service_dispatch, args=(data,))
        t.start()

        # self.service_dispatch( json.loads( data ) )

        return

    def register_agent( self, agent_type: AgentType ):

        # todo: check BuildConfig if everything is by rule

        if self.RegisteredAgent is None:
            print( "[*] register agent" )

            self.RegisteredAgent = agent_type
            self.RegisteredAgent._Service_instance = self

            request = json.dumps(
                build_request( "RegisterAgent", {
                    "Agent": agent_type.get_dict()
                } ),
                sort_keys=True
            )

            self.Socket.send( request )
        else:
            print( "[!] Agent already registered" )

        return

    def register_externalc2( self, externalc2: ExternalC2, agent_type = {0:0} ):

        if self.ExternalC2 is None:

            self.ExternalC2 = externalc2
            self.ExternalC2._Service_instance = self

            request = json.dumps(
                build_request("RegisterAgent", {
                    "Agent": agent_type.get_dict()
                }),
                sort_keys=True
            )

            self.Socket.send(request)
        else:
            print( "[-] External C2 already registered" )

        return

    def service_dispatch( self, data: dict ):

        match data[ "Head" ][ "Type" ]:

            case "Register":

                self.Connected = data[ "Body" ][ "Success" ]

                return

            case "RegisterAgent":
                return

            case "Agent":

                match data[ "Body" ][ "Type" ]:

                    case "AgentTask":

                        if data[ "Body" ][ "Task" ] == "Get":
                            RandID = data[ "Body" ][ "RandID" ]
                            Tasks  = base64.b64decode( data[ "Body" ][ "TasksQueue" ] )

                            print( f"Set TasksQueue to {RandID} = {Tasks.hex()}" )

                            self.RegisteredAgent._current_data[ RandID ] = Tasks

                        elif data[ "Body" ][ "Task" ] == "Add":
                            data[ "Body" ][ "Command" ] = base64.b64encode( self.RegisteredAgent.task_prepare( data[ 'Body' ][ 'Command' ] ) ).decode( 'utf-8' )

                        self.Socket.send( json.dumps( data ) )

                    case "AgentResponse":

                        agent_response = self.RegisteredAgent.response( data[ "Body" ] )
                        data[ "Body" ][ "Response" ] = base64.b64encode( agent_response ).decode( 'utf-8' )

                        self.Socket.send( json.dumps( data ) )

                    case "AgentBuild":

                        self.RegisteredAgent.generate( data[ "Body" ] )

        return