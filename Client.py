import socket


class Client:
    def __init__(self):
        self.PORT = 1234
        self.MESSAGE_LENGTH_SIZE = 64
        self.ENCODING = 'utf-8'
        self.ADDRESS = socket.gethostbyname(socket.gethostname())
        self.SERVER_INFORMATION = (self.ADDRESS, self.PORT)
    
    def main(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.SERVER_INFORMATION)
        self.send_message(s, 'HELLO SERVER:)')
        self.send_message(s, 'DISCONNECT')
    
    def send_message(self, c, msg):
        message = msg.encode(self.ENCODING)
        msg_length = len(message)
        msg_length = str(msg_length).encode(self.ENCODING)
        msg_length += b' ' * (self.MESSAGE_LENGTH_SIZE - len(msg_length))
        c.send(msg_length)
        c.send(message)


if __name__ == '__main__':
    client = Client()
    client.main()
    