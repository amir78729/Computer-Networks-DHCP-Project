import socket
import threading

class Server:
    def __init__(self):
        self.PORT = 1234
        self.MESSAGE_LENGTH_SIZE = 64
        self.ENCODING = 'utf-8'
        self.ADDRESS = socket.gethostbyname(socket.gethostname())
        self.HOST_INFORMATION = (self.ADDRESS, self.PORT)

    def main(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(self.HOST_INFORMATION)
        print('[SERVER STARTS] Server is starting...')
        server.listen()
        while True:
            conn, address = server.accept()
            t = threading.Thread(target=self.handle_client, args=(conn, address))
            t.start()
    
            

    def handle_client(self, conn, address):
        print('[NEW CONNECTION] connected from {}.'.format(address))
        connected = True
        while connected:
            try:
                message_length = int(conn.recv(self.MESSAGE_LENGTH_SIZE).decode(self.ENCODING))
                msg = conn.recv(message_length).decode(self.ENCODING)
                print('[MESSAGE RECIEVED] {}'.format(msg))
                if msg == 'DISCONNECT':
                    connected = False
            except Exception as e:
                print(e)
        conn.close()

if __name__ == '__main__':
    server = Server()
    server.main()
    