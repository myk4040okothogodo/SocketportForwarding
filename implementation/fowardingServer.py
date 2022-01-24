import socket
import os
import signal
import threading
import hashlib
import fcntl
import struct

from Crypto import Random
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from lazyme.string import color_print

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', ifname[:15])
        )[20:24])

def RemovePadding(s):
    return s.replace(' ','')

def Padding(s):
    return s + ((16 - len(s) % 16) * ' ')
    
    
    
def connectwithEndServer():  
    def RemovePadding(s):
        return s.replace(' ','')


    def Padding(s):
        return s + ((16 - len(s) % 16) * ' ')


    def  ReceiveMessage():
        while True:
            emsg = server.recv(1024)
            msg = RemovePadding(AESkey.decrypt(emsg))
            if msg == FLAG_QUIT:
                color_print("\n[!] Server was shutdown by admin", color="red", underline=True)
                os.kill(os.getpid(), signal.SIGKILL)
            else:
                #color_print("\n[!] Servers encrypted message \n"+ emsg, color="gray")
                print ("\n[!] SERVER SAID  : ", msg)
        return emsg        


    def SendMessage(): #message from endclient to end server
        while True:
            
            msg = broadcast_usr()
            en = AESKey.encrypt(padding(msg))
            server.send(str(en))
            if msg == FLAG_QUIT:
                os.kill(os.getpid(), signal.SIGKILL)
            else:
                color_print("\n[!] Your encrypted message \n" + en, color="gray")


    if __name__ == "__main__":
        #objects
        server = " "
        AESKey = " "
        FLAG_READY = "Ready"
        FLAG_QUIT = "quit"
        #10.1.236.227
        #public key and private key

        random = Random.new().read
        RSAkey = RSA.generate(1024, random)
        public = RSAkey.publickey().exportKey()
        private = RSAkey.exportKey()

        tmpPub = hashlib.md5(public)
        my_hash_public = tmpPub.hexdigest()


        print (public)
        print ("\n",private)


        host = input("Host : ")
        port = int(input("Port : "))

        host = "127.0.0.1"
        port = 5599
        #
        with open('private.txt', 'w'):
            pass
        with open('public.txt', 'w'):
            pass

        try:
            file = open('private.txt', 'w')
            file.write(private)
            file.close()


            file = open('public.txt', 'w')
            file.write(public)
            file.close()
        except BaseException:
            color_print("key storing in failed", color="red", underline=True)

        check = False

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect((host, port))
            check = True

        except BaseException:
            color_print("\n[!] Check Server Address or Port", color="red", underline=True)

        if check is True:
            color_print("\n[!] Connection Successful", color="green", bold=True)
            server.send(public + ":".encode() + my_hash_public)
            # receive server public key, hash of public , eight byte and hash of eight byte
            fGet =server.recv(4072)
            split = fGet.split(":")
            toDecrypt = split[0]
            serverPublic = split[1]

            color_print("\n[!] Servers public key \n", color="blue")
            print (serverPublic)
            decrypted = RSA.importKey(private).decrypt(eval(toDecrypt.replace("\r\n", '')))
            splittedDecrypt = decrypted.split(":")
            eightByte = splittedDecrypt[0]
            hashOfEight = splittedDecrypt[1]
            hashOfPublic = splittedDecrypt[2]
            color_print ("\n[!] Clients Eight byte key in hash \n", color="blue")
            print (hashOfEight)


            # hashing for checking
            sess = hashlib.md5(eightByte)
            session = sess.hexdigest()

            hashObj = hashlib.md5(serverPublic)
            server_public_hash = hashObj.hexdigest()
            color_print("\n[!] Matching servers public key and eight byte key\n", color="blue")
            if server_public_hash == hashOfPublic and session == hashOfEight:
            # encrypt back the eight byte kkey with the server public key and send it
                color_print("\n[!] Sending encrpted session key\n", color="blue")
                serverPublic = RSA.importKey(serverPublic).encrypt(eightByte, None)
                server.send(str(serverPublic))

                #creating 128 bits key with 16 bytes
                color_print("\[!] Creating AES key\n", color="blue")
                key_128 = eightByte + eightByte[::-1]
                AESKey = AES.new(key_128, AES.MODE_CBC, IV=key_128)

                #receiving ready
                serverMsg = server.recv(2048)
                serverMsg = RemovePadding(AESkey.decrypt(serverMsg))
                if serverMsg == FLAG_READY:
                    color_print("\n[!] Server is ready to communicate\n", color="blue")
                    serverMsg = input("\n[>] Enter Your Name : ")
                    server.send(serverMsg)
                    threading_rec = threading.Thread(target=ReceiveMessage)
                    threading_rec.start()
                    threading_send = threading.Thread(target = SendMessage)
                    threading_send.start()
                else:
                    color_print("\n Server (Public key && Public key hash) || (Session key && Hash of Session key) doesnt match", color="red", underline=True)    


def ConnectionSetup():
    while True:
        if check is True:
            client, address = server.accept()
            color_print("\n[!] One client is trying to connect.....", color="green", bold=True)
            #get client public key and the hash of it
            clientPH = client.recv(2048)
            split = clientPH.split(":")
            tmpClientPublic = split[0]
            clientPublicHash = split[1]
            color_print("\n[!] Anonymous client's public key\n", color="blue")
            print (tmpClientPublic )
            tmpClientPublic = tmpClientPublic.replace("\r\n", '')
            clientPublicHash = clientPublicHash.replace("\r\n",'')
            tmpHashObject = hashlib.md5(tmpClientPublic)
            tmpHash = tmpHashObject.hexdigest()

            if tmpHash == clientPublicHash:
                #sending public key, encrypted eight byte , hash of eight byte and server public key hash
                color_print("\n[!] Anonymous clients public key and public key hash matches\n", color="blue")
                clientPublic = RSA.importKey(tmpClientPublic)
                fSend = eightByte + ":" + session + ":" + my_hash_public
                fSend = clientPublic.encrypt(fSend, None)
                client.send(str(fSend) + ":" + public)

                clientPH = client.recv(2048)
                if clientPH != "":
                    clientPH = RSA.importKey(private).decrypt(eval(clientPH.decode('utf-8')))
                    color_print("\n[!] Matching session key\n", color="blue")
                    if clientPH == eightByte:
                        #creating 128 bits key with 16 bytes
                        color_print("\n[!] Creating AES key\n", color="blue")
                        key_128 = eightByte + eightByte[::-1]
                        AESKey = AES.new(key_128, AES.MODE_CBC, IV=key_128)
                        clientMsg = AESKey.encrypt(Padding(FLAG_READY))
                        client.send(clientMsg)
                        color_print("\n[!] Waaiting  for clients name\n", color="blue")
                        # client name
                        clientMsg = client.recv(2048)
                        CONNECTION_LIST.append(( clientMsg, client))
                        color_print("\n"+ clientMsg+" IS CONNECTED", color="green", underline=True)
                        
                        
                        threading_client = threading.Thread(target=broadcast_usr, args=[clientMsg,client, AESKey])
                        threading_client.start()
                        threading_message = threading.Thread(target= send_message, args=[client, AESKey])
                        threading_message.start()
                        

                    else:
                        color_print("\nSession key from client doesnt match", color="red", underline=True)

            else:
                color_print("\nPublic key and public hash doesnt match", color="red", underline=True)
                client.close()
                
                
              

def send_message(socketClient, AESk):
    while True:
        msg = connectwithEndServer.ReceiveMessage()
        en = AESk.encrypt(_Padding(msg))
        socketClient.send(str(en))
        if msg == FLAG_QUIT:
            os.kill(os.getpid(), signal.SIGKILL)
        #else:
          #  color_print("\n[!] Your encrypted message \n"+ en, color="gray")

def broadcast_usr(uname, socketClient, AESk):
    while True:
        try:
            data = socketClient.recv(1024)
            en = data
            if data:
                data = RemovePadding(AESk.decrypt(data))
                if data == FLAG_QUIT:
                    color_print("\n"+ uname +" left the conversation", color="red", underline=True)
                else:
                    b_usr(socketClient, uname, data)
                    print ("\n[!]", uname, " SAID :", data)
                    color_print("\n[!] Client's encrpted message\n"+ en, color="gray")
            return data         
        except Exception as x:
            print(x.message)
            break
            


def b_usr(cs_sock, sen_name, msg):
    for client in CONNECTION_LIST:
        if client[1] != cs_sock:
            client[1].send(sen_name)
            client[1].send(msg)

    
if __name__ == "__main__":
    #objects
    host = " "
    port = 0
    server = ""
    AESKey = ""
    CONNECTION_LIST = []
    FLAG_READY = "Ready"
    FLAG_QUIT= "quit"
    YES = "1"
    NO = "2"

    # 10.1.236.227
    # public key and private key
    random = Random.new().read
    RSAkey = RSA.generate(1024, random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()

    tmpPub = hashlib.md5(public)
    my_hash_public = tmpPub.hexdigest()


    eightByte = os.urandom(8)
    sess = hashlib.md5(eightByte)
    session = sess.hexdigest()

    with open('private.txt', 'w'):
        pass 
    with open('public.txt', 'w'):
        pass

    try:
        file = open('private.txt', 'w')
        file.write(private)
        file.close()

        file = open('public.txt', 'w')
        file.write(public)
        file.close()


    except BaseException:
        color_print("Key storing in failed", color="red", underline=True)
    check = False
    color_print("Middle server up, type yes to set up pipe",  color="blue", bold=True)

    host = 'localhost'
    port = 8080
        #color_print("[!] Invalid selection", color="red", underline=True)
       # os.kill(os.getpid(), signal.SIGKILL)

    print ("\n",public, "\n\n", private)
    color_print("\n[!] Eight byte session key in hash\n", color="blue")
    print (session)
    color_print("\n[!] Server IP"+ host+" & PORT"+ str(port), color="green", underline=True)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(( host, port))
    server.listen(1)

    color_print("\n[!] Server Connection Successful", color="green", bold=True)
    check = True

    # accept clients
    threading_accept = threading.Thread(target=ConnectionSetup)
        
    threading_accept.start()
    threading_send = threading.Thread(target= connectwithEndServer)
