import http.client
import socket


class Connection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect("/run/warden-keys/service.sock")


connection = Connection("localhost", timeout=3)
connection.request("GET", "/health")
response = connection.getresponse()
assert response.status == 200
connection.close()
