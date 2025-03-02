import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import configparser
import logging.handlers
from contextlib import contextmanager
import logging

# 協議常量
SOCKS_VERSION = 5
AUTHENTICATION_VERSION = 0x01

# 命令類型
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# 地址類型
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# 認證方法
AUTH_NONE = 0x00
AUTH_PASSWORD = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

# 回覆碼
REPLY_SUCCESS = 0x00
REPLY_SERVER_FAILURE = 0x01
REPLY_CONN_NOT_ALLOWED = 0x02
REPLY_NETWORK_UNREACHABLE = 0x03
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONN_REFUSED = 0x05
REPLY_TTL_EXPIRED = 0x06
REPLY_CMD_NOT_SUPPORTED = 0x07
REPLY_ADDR_TYPE_NOT_SUPPORTED = 0x08

# 超時設置（秒）
TIMEOUT_CONNECT = 30
TIMEOUT_READ = 300
TIMEOUT_UDP = 60

# 緩衝區大小
BUFFER_SIZE = 65536

def setup_logging():
    config = configparser.ConfigParser()
    config.read('s5.ini', encoding='utf-8')
    
    if config.has_section('Logging') and config.getboolean('Logging', 'EnableLogging', fallback=False):
        log_level = config.get('Logging', 'LogLevel', fallback='DEBUG')
        numeric_level = getattr(logging, log_level.upper(), logging.DEBUG)
        
        log_handler = logging.handlers.RotatingFileHandler('socks5.log', maxBytes=1024*1024, backupCount=5)
        log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
        log_handler.setFormatter(log_formatter)
        logging.basicConfig(level=numeric_level, handlers=[log_handler, logging.StreamHandler()])
    else:
        logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.load_config()

    def load_config(self):
        self.config = configparser.ConfigParser()
        self.config.read('s5.ini', encoding='utf-8')
        self.enable_validation = self.config.getboolean('Authentication', 'EnableValidation', fallback=False)
        self.auth_config = {
            'username': self.config.get('Authentication', 'Username', fallback=''),
            'password': self.config.get('Authentication', 'Password', fallback='')
        } if self.enable_validation else {}
        self.port = self.config.getint('Server', 'Port', fallback=30678)
        self.ipv4_bind = self.config.get('Server', 'IPv4_Bind', fallback='0.0.0.0')
        self.ipv6_bind = self.config.get('Server', 'IPv6_Bind', fallback='::')

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except AttributeError:
            pass
        super().server_bind()

class SocksProxy(StreamRequestHandler):
    def handle(self):
        client_conn = self.connection
        client_addr = self.client_address
        logging.info(f'新連接來自 {client_addr}')

        try:
            if not self.handle_socks_init(client_conn):
                return
            if not self.handle_request(client_conn):
                return
        except Exception as e:
            logging.error(f"處理連接時發生錯誤: {str(e)}")
        finally:
            self.close_connection()

    def handle_socks_init(self, client_conn):
        try:
            header = client_conn.recv(2)
            if len(header) != 2:
                return False

            version, nmethods = struct.unpack("!BB", header)
            if version != SOCKS_VERSION:
                return False

            methods = self.get_auth_methods(client_conn, nmethods)
            return self.handle_authentication(client_conn, methods)

        except Exception as e:
            logging.error(f"初始化階段錯誤: {str(e)}")
            return False

    def handle_authentication(self, client_conn, methods):
        enable_validation = self.server.enable_validation

        if enable_validation:
            if AUTH_PASSWORD not in methods:
                client_conn.sendall(struct.pack("!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE))
                return False
            client_conn.sendall(struct.pack("!BB", SOCKS_VERSION, AUTH_PASSWORD))
            return self.handle_auth(client_conn)
        else:
            if AUTH_NONE not in methods:
                client_conn.sendall(struct.pack("!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE))
                return False
            client_conn.sendall(struct.pack("!BB", SOCKS_VERSION, AUTH_NONE))
            return True

    def get_auth_methods(self, conn, n):
        methods = []
        for _ in range(n):
            method = conn.recv(1)
            if not method:
                break
            methods.append(ord(method))
        return methods

    def handle_auth(self, conn):
        try:
            auth_version = ord(conn.recv(1))
            if auth_version != AUTHENTICATION_VERSION:
                return False

            username_len = ord(conn.recv(1))
            username = conn.recv(username_len).decode('utf-8', errors='ignore')
            password_len = ord(conn.recv(1))
            password = conn.recv(password_len).decode('utf-8', errors='ignore')
            
            auth_config = self.server.auth_config
            if (username == auth_config.get('username') and 
                password == auth_config.get('password')):
                conn.sendall(struct.pack("!BB", AUTHENTICATION_VERSION, REPLY_SUCCESS))
                return True
            
            conn.sendall(struct.pack("!BB", AUTHENTICATION_VERSION, AUTH_NO_ACCEPTABLE))
            return False

        except Exception as e:
            logging.error(f"認證過程中發生錯誤: {str(e)}")
            return False

    def parse_address(self, conn, addr_type):
        try:
            if addr_type == ATYP_IPV4:
                addr = socket.inet_ntoa(conn.recv(4))
            elif addr_type == ATYP_DOMAIN:
                domain_len = ord(conn.recv(1))
                addr = conn.recv(domain_len).decode('utf-8', errors='ignore')
            elif addr_type == ATYP_IPV6:
                addr = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
            else:
                return None

            port_data = conn.recv(2)
            if len(port_data) != 2:
                return None
                
            port = struct.unpack("!H", port_data)[0]
            return (addr, port)

        except Exception as e:
            logging.error(f"解析地址時發生錯誤: {str(e)}")
            return None

    def handle_request(self, client_conn):
        try:
            header = client_conn.recv(4)
            if len(header) != 4:
                return False

            version, cmd, _, addr_type = struct.unpack("!BBBB", header)
            if version != SOCKS_VERSION:
                return False

            target_addr = self.parse_address(client_conn, addr_type)
            if not target_addr:
                self.send_reply(client_conn, REPLY_ADDR_TYPE_NOT_SUPPORTED, addr_type)
                return False

            if cmd == CMD_CONNECT:
                return self.handle_connect(client_conn, target_addr)
            elif cmd == CMD_UDP_ASSOCIATE:
                return self.handle_udp_associate(client_conn)
            else:
                self.send_reply(client_conn, REPLY_CMD_NOT_SUPPORTED, addr_type)
                return False

        except Exception as e:
            logging.error(f"處理請求時發生錯誤: {str(e)}")
            return False

    @contextmanager
    def create_remote_connection(self, target_addr):
        sock = socket.socket(socket.AF_INET6 if ':' in target_addr[0] else socket.AF_INET)
        sock.settimeout(TIMEOUT_CONNECT)
        try:
            sock.connect(target_addr)
            yield sock
        finally:
            sock.close()

    def handle_connect(self, client_conn, target_addr):
        try:
            with self.create_remote_connection(target_addr) as remote_sock:
                bind_addr = remote_sock.getsockname()
                
                if ':' in bind_addr[0]:
                    addr_type = ATYP_IPV6
                    addr_bytes = socket.inet_pton(socket.AF_INET6, bind_addr[0])
                else:
                    addr_type = ATYP_IPV4
                    addr_bytes = socket.inet_aton(bind_addr[0])

                reply = struct.pack("!BBB", SOCKS_VERSION, REPLY_SUCCESS, 0x00)
                reply += struct.pack("!B", addr_type) + addr_bytes
                reply += struct.pack("!H", bind_addr[1])
                client_conn.sendall(reply)

                self.relay_data(client_conn, remote_sock)
                return True

        except (socket.timeout, ConnectionRefusedError) as e:
            logging.error(f"連接到 {target_addr} 失敗: {str(e)}")
            self.send_reply(client_conn, REPLY_CONN_REFUSED, ATYP_IPV4)
        except Exception as e:
            logging.error(f"處理CONNECT命令時發生錯誤: {str(e)}")
            self.send_reply(client_conn, REPLY_SERVER_FAILURE, ATYP_IPV4)
        return False

    def relay_data(self, client_conn, remote_sock):
        try:
            client_conn.settimeout(TIMEOUT_READ)
            remote_sock.settimeout(TIMEOUT_READ)
            
            while True:
                r, _, e = select.select(
                    [client_conn, remote_sock], 
                    [], 
                    [client_conn, remote_sock], 
                    TIMEOUT_READ
                )
                
                if e:
                    logging.error("數據轉發時發生錯誤")
                    break
                    
                if not r:  # 超時
                    continue
                    
                for sock in r:
                    other = remote_sock if sock == client_conn else client_conn
                    try:
                        with memoryview(bytearray(BUFFER_SIZE)) as data:
                            nbytes = sock.recv_into(data)
                            if nbytes == 0:
                                return
                            other.sendall(data[:nbytes])
                    except socket.error as e:
                        logging.error(f"數據轉發錯誤: {str(e)}")
                        return

        except Exception as e:
            logging.error(f"數據轉發時發生錯誤: {str(e)}")

    def handle_udp_associate(self, client_conn):
        try:
            # 創建UDP socket並配置
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # 獲取客戶端地址
            client_ip = self.client_address[0]
            if ':' in client_ip:
                client_ip = client_ip.replace('::ffff:', '')
            
            # 綁定地址處理（參考 s5.py 實現，綁定到本地可用地址）
            bind_addr = None
            if client_ip == '127.0.0.1':
                bind_addr = ('127.0.0.1', 0)
            elif ':' in client_ip:
                bind_addr = ('::', 0)
                udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                udp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            else:
                bind_addr = ('0.0.0.0', 0)
            
            if not bind_addr:
                raise ValueError("無法確定綁定地址")
            
            udp_sock.bind(bind_addr)
            bind_ip, bind_port = udp_sock.getsockname()
            
            # 設置超時
            udp_sock.settimeout(TIMEOUT_UDP)
            
            # 確定回應地址（參考 s5.py，使用服務器設定的IPv4地址作為回覆）
            reply_ip = self.server.ipv4_bind
            if reply_ip == '0.0.0.0':
                if client_ip == '127.0.0.1':
                    reply_ip = '127.0.0.1'
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        s.connect((client_ip, 1))
                        reply_ip = s.getsockname()[0]
                    except:
                        reply_ip = socket.gethostbyname(socket.gethostname())
                    finally:
                        s.close()

            # 發送UDP關聯回覆
            reply = struct.pack("!BBB", SOCKS_VERSION, REPLY_SUCCESS, 0x00)
            reply += struct.pack("!B", ATYP_IPV4)
            reply += socket.inet_aton(reply_ip)
            reply += struct.pack("!H", bind_port)
            client_conn.sendall(reply)

            logging.info(f"UDP關聯: 客戶端={client_ip}, 監聽={bind_ip}:{bind_port}, 回覆={reply_ip}:{bind_port}")
            
            # 參考 s5.py 的簡單阻塞模式，直接使用單一udp_sock進行收發
            self.udp_relay_loop(udp_sock)
            return True

        except Exception as e:
            logging.error(f"處理UDP ASSOCIATE命令時發生錯誤: {str(e)}")
            self.send_reply(client_conn, REPLY_SERVER_FAILURE, ATYP_IPV4)
            return False

    def udp_relay_loop(self, udp_sock):
        """
        非阻塞式UDP轉發:
        - 使用select進行非阻塞IO
        - 優化緩衝區大小
        - 高效數據包處理
        """
        # 設置非阻塞模式
        udp_sock.setblocking(False)
        
        # 增大緩衝區
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
        
        # 保存客戶端和目標的映射關係
        client_targets = {}  # {client_addr: (target_addr, target_port)}
        target_clients = {}  # {(target_addr, target_port): client_addr}
        
        while True:
            try:
                # 使用較短的超時時間以提高響應性
                readable, _, _ = select.select([udp_sock], [], [], 0.1)
                if not readable:
                    continue
                
                data, addr = udp_sock.recvfrom(65536)
                
                # 處理來自已知客戶端的數據
                if addr in client_targets:
                    target = client_targets[addr]
                    if len(data) >= 4:
                        # 解析SOCKS5 UDP數據包
                        if data[0] == 0 and data[1] == 0 and data[2] == 0:
                            # 跳過頭部獲取負載
                            pos = 3  # RSV(2) + FRAG(1)
                            atyp = data[pos]
                            pos += 1
                            # 根據地址類型跳過相應字節
                            if atyp == ATYP_IPV4:
                                pos += 4
                            elif atyp == ATYP_DOMAIN:
                                pos += 1 + data[pos]
                            elif atyp == ATYP_IPV6:
                                pos += 16
                            pos += 2  # 跳過端口
                            # 發送實際負載給目標
                            payload = data[pos:]
                            if payload:
                                udp_sock.sendto(payload, target)
                    continue

                # 處理來自目標的回應
                source = (addr[0], addr[1])
                if source in target_clients:
                    client_addr = target_clients[source]
                    # 構造SOCKS5 UDP回應包
                    header = struct.pack("!HBB", 0, 0, ATYP_IPV4 if ':' not in addr[0] else ATYP_IPV6)
                    if ':' in addr[0]:
                        header += socket.inet_pton(socket.AF_INET6, addr[0])
                    else:
                        header += socket.inet_aton(addr[0])
                    header += struct.pack("!H", addr[1])
                    response = header + data
                    udp_sock.sendto(response, client_addr)
                    continue

                # 處理新連接
                if len(data) >= 4 and data[0] == 0 and data[1] == 0 and data[2] == 0:
                    pos = 3
                    atyp = data[pos]
                    pos += 1
                    target_addr = None
                    
                    try:
                        if atyp == ATYP_IPV4 and len(data) >= pos + 4 + 2:
                            target_addr = socket.inet_ntoa(data[pos:pos+4])
                            pos += 4
                        elif atyp == ATYP_DOMAIN and len(data) >= pos + 1:
                            domain_len = data[pos]
                            pos += 1
                            if len(data) >= pos + domain_len + 2:
                                domain = data[pos:pos+domain_len].decode()
                                target_addr = socket.gethostbyname(domain)
                                pos += domain_len
                        elif atyp == ATYP_IPV6 and len(data) >= pos + 16 + 2:
                            target_addr = socket.inet_ntop(socket.AF_INET6, data[pos:pos+16])
                            pos += 16
                            
                        if target_addr and len(data) >= pos + 2:
                            target_port = struct.unpack("!H", data[pos:pos+2])[0]
                            pos += 2
                            target = (target_addr, target_port)
                            
                            # 更新映射關係
                            client_targets[addr] = target
                            target_clients[target] = addr
                            
                            # 轉發負載
                            payload = data[pos:]
                            if payload:
                                udp_sock.sendto(payload, target)
                                
                    except Exception as e:
                        logging.error(f"處理新UDP連接失敗: {e}")
                        continue

            except Exception as e:
                logging.error(f"UDP轉發出錯: {e}")
                break

    def send_reply(self, conn, rep, atyp):
        try:
            reply = struct.pack("!BBBB", SOCKS_VERSION, rep, 0x00, atyp)
            reply += struct.pack("!I", 0) + struct.pack("!H", 0)
            conn.sendall(reply)
        except Exception as e:
            logging.error(f"發送回覆失敗: {str(e)}")

    def close_connection(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            logging.debug(f"關閉連接時發生錯誤: {str(e)}")
        finally:
            self.connection.close()

def main():
    setup_logging()
    config = configparser.ConfigParser()
    config.read('s5.ini', encoding='utf-8')
    port = config.getint('Server', 'Port', fallback=30678)
    ipv4_bind = config.get('Server', 'IPv4_Bind', fallback='0.0.0.0')
    ipv6_bind = config.get('Server', 'IPv6_Bind', fallback='::')
    
    try:
        try:
            address = (ipv6_bind, port)
            server = ThreadingTCPServer(address, SocksProxy)
            logging.info(f"SOCKS5 服務器運行在 [{ipv6_bind}]:{port} (雙棧模式)")
        except (socket.gaierror, OSError):
            ThreadingTCPServer.address_family = socket.AF_INET
            address = (ipv4_bind, port)
            server = ThreadingTCPServer(address, SocksProxy)
            logging.info(f"SOCKS5 服務器運行在 {ipv4_bind}:{port} (IPv4模式)")
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("服務器正在關閉...")
        server.shutdown()
        server.server_close()
    except Exception as e:
        logging.error(f"服務器運行時發生錯誤: {str(e)}")
        raise

if __name__ == '__main__':
    main()
