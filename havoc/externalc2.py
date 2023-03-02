import base64

import requests


class ExternalC2:
    Server: str = ''

    def __init__( self, server ) -> None:
        self.Server = server
        return

    def transmit( self, data ) -> bytes:
        agent_response = b''

        try:
            response = requests.post( self.Server, data=data )
            agent_response = base64.b64decode(response.text)

        except Exception as e:
            print( f"[-] Exception: {e}" )

        return agent_response

