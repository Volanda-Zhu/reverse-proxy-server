import socket
import threading
import re


# process data
def recv_data(connection):
    """
    get data from client
    :return:
    """
    # init client data with empty byte-like strings
    client_data = b''
    while 1:
        data = connection.recv(1024) # wait for accecpting the data, maximum length is 10248

        client_data = client_data + data

        # check content length to stop while
        try:
            content_lenth = re.findall(b'Content-Length:[\s\S]*?(\d+)', client_data)[0]
        except:
            content_lenth = 0
        if data.endswith(b'\r\n\r\n') and content_lenth == 0:
            break
        else:
            if len(client_data.split(b'\r\n')[-1]) == int(content_lenth):
                break

    return client_data


def parse_header_data(header_data):
    """
    parse client header data
    :param client_data:
    :return:
    """
    #  strip, decode , split data by \r\n
    headers = {}
    header_data = header_data.strip().decode().split('\r\n')
    print(header_data)
    # parse header
    try:
        headers['METHOD_CONTENT'] = header_data[0]
        headers['Method'] = headers['METHOD_CONTENT'].split(' ')[0]  # CONNECT/GET
        headers['Http_Version'] = headers['METHOD_CONTENT'].split(' ')[2]  # CONNECT/GET
        headers['Url'] = headers['METHOD_CONTENT'].split(' ')[1]

        for item in header_data[1:]:
            item = item.split(':')
            headers[item[0]] = item[1].lstrip()
        if 'CONNECT' in headers['METHOD_CONTENT']:  # if https
            headers['Port'] = 443  #
        else:
            headers['Port'] = 80

        print(headers)

    # if error occurs
    except Exception as err:
        print('there is something wrong: ', err)

    return headers


def build_request_header(header_data):
    header = ''
    header += f"{header_data['METHOD_CONTENT']}\r\n"
    header += f"Host: {header_data['Host']}\r\n"
    header += f'Connection: close\r\n'
    header += f'Upgrade-Insecure-Requests: 1\r\n'
    header += f'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:75.0) Gecko/20100101 Firefox/75.0\r\n'
    header += f'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n'
    header += f'Accept-Encoding: gzip, deflate, br\r\n'
    header += f'Accept-Language: en-US,en;q=0.9\r\n'
    header += f'MyProxy:1D3W2ADW1S32S1S41Q23B2Y2N1K3O\r\n'
    header += '\r\n'
    header = header.encode('utf-8')
    return header


def inter_socket(recv_from, send_to, recv_from_response=False):
    """
    intereact with sockets
    :param recv_from: client or target side
    :param send_to: client or target side
    :param recv_from_response: if close
    :return:
    """
    all_data = b''
    try:
        while True:
            buf = recv_from.recv(1024*4)
            all_data = all_data + buf
            send_to.send(buf)
            if not buf:
                break
    except Exception as err:
        recv_from.close()  # close connection
        send_to.close()  # close connection
        return
    if recv_from_response:
        recv_from.close()
        send_to.close()

    print(f'========== Response From Original Server: ================ ')
    print(all_data)
    print(f'========== END OF Response From Original Server==========\n')

    print(f'\n ========== Send To Client : Done ================ \n')


def proxy_handler(client_connection, addr):
    """
    main function
    :param socketServer: socket object
    :return:
    """
    # connection(socket object) send and receive data on the connection
    # addr is address bound to the socket on the other end of the connection.
    print(f'WEB PROXY SERVER CONNECTED WITH  {addr[0]}:{addr[1]}  \n')
    # receive data from client

    # all_data = client_connection.recv(4000)
    all_data = recv_data(client_connection)

    print(f'========== MESSAGE RECEIVED FROM CLIENT: ================ ')
    print(all_data.strip())
    print(f'========== END OF MESSAGE RECEIVED FROM CLIENT ========== \n')

    # parse data from client
    header_data = parse_header_data(all_data)
    print(f'========== Parse Message FROM CLIENT: ================ ')
    print(header_data)
    print(f'========== END OF Parse Message FROM CLIENT ========== \n')

    fake_header = build_request_header(header_data)  # build fake header
    print(f'========== Send Request To Original Server: ================ ')
    print(fake_header)
    print(f'========== END OF Send Request To Original Server========== \n')

    # check if host or url contain cloudflare.com
    if 'cloudflare.com' in header_data['Host'] or 'cloudflare.com' in header_data['Url']:
        client_connection.send(b"HTTP/1.1 200 Connection Stop\r\nConnection: close\r\n\r\n")
        client_connection.close()
    else:
        # a new socket to sent request to original server
        tmpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmpSocket.settimeout(20)  # set connection timeout
        tmpSocket.connect((header_data['Host'], int(header_data['Port'])))  # connect

        # if it is https
        if header_data['Method'] == 'CONNECT':
            client_connection.send(b"HTTP/1.1 200 Connection established\r\nConnection: close\r\n\r\n")
        else:
            tmpSocket.send(fake_header)

        # proxy client connection to
        threading.Thread(target=inter_socket, args=(client_connection, tmpSocket, False)).start()
        threading.Thread(target=inter_socket, args=(tmpSocket, client_connection, True)).start()


def runServer(HOST, PORT):
    """
    run server
    :param HOST: host
    :param PORT: port
    :return:
    """
    # CREAT a socket object, AF_INET: IPV4, SOCK_STREAM: TCP type
    socketServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # BIND local address e.g. 127.0.0.1:5050
    socketServer.bind((HOST, PORT))
    # LISTEN and set the number of backlog
    socketServer.listen(10)
    # Starting receive message from client
    print('PROXY SERVER IS NOW LISTENING \n')

    while True:
        # connection(socket object) send and receive data on the connection
        # addr is address bound to the socket on the other end of the connection.
        client_connection, addr = socketServer.accept() # wait for clients(when the client gets connected, returned the tuple)

        # main function to handle proxy
        threading.Thread(target=proxy_handler, args=(client_connection, addr)).start()


if __name__ == '__main__':
    runServer('127.0.0.1', 5008)



