import socket
import struct
import logging
import ssl
import time
import ipaddress
import urllib.parse
from typing import Union, Tuple, Dict, Optional

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
test_url = 'google.com'
test_dns = '8.8.8.8'

class Socks5Client:
    def __init__(self, server_addr='192.168.1.99', server_port=30678):
        self.server_addr = server_addr
        self.server_port = server_port
        self.socket = None
        self.timeout = 10
        self.buffer_size = 32768
        self.retry_interval = 1
        self.max_retries = 3
        self.tcp_keepalive = True
        self.tcp_nodelay = True
        self.ssl_context = None

    def connect(self, retries=3, timeout=5):
        """建立到 SOCKS5 伺服器的連接"""
        last_error = None
        for attempt in range(retries):
            try:
                # 嘗試判斷是否為IPv6地址
                try:
                    # 如果是IPv6地址, 使用AF_INET6
                    ipaddress.IPv6Address(self.server_addr)
                    self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    logger.debug(f"使用IPv6連接到代理伺服器: {self.server_addr}")
                except ValueError:
                    # 不是IPv6地址, 使用AF_INET
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                self.socket.settimeout(timeout)
                
                # 設置 TCP 參數
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
                
                logger.info(f"嘗試連接 SOCKS5 伺服器 {self.server_addr}:{self.server_port} (第 {attempt + 1} 次)")
                self.socket.connect((self.server_addr, self.server_port))
                
                logger.info(f"成功連接到 SOCKS5 伺服器 {self.server_addr}:{self.server_port}")
                return True
                
            except Exception as e:
                last_error = e
                logger.error(f"連接 SOCKS5 伺服器失敗 (第 {attempt + 1} 次): {e}")
                if self.socket:
                    self.socket.close()
                    self.socket = None
                if attempt < retries - 1:
                    import time
                    time.sleep(1)  # 重試前等待
                    
        logger.error(f"連接 SOCKS5 伺服器失敗，已重試 {retries} 次: {last_error}")
        return False

    def auth(self):
        """進行 SOCKS5 認證"""
        try:
            # 設置超時
            self.socket.settimeout(self.timeout)
            
            # 構建認證請求
            auth_request = struct.pack('!BBB', 0x05, 0x01, 0x00)
            logger.debug(f"發送認證請求: {' '.join(f'{b:02x}' for b in auth_request)}")
            
            # 確保完整發送
            total_sent = 0
            while total_sent < len(auth_request):
                sent = self.socket.send(auth_request[total_sent:])
                if sent == 0:
                    raise Exception("連接已關閉")
                total_sent += sent
            
            # 接收並驗證回應
            response = self._recv_exact(2)
            version, auth_method = struct.unpack('!BB', response)
            logger.debug(f"收到認證回應: version=0x{version:02x}, method=0x{auth_method:02x}")
            
            if version != 0x05:
                raise Exception(f"不支持的協議版本: 0x{version:02x}")
            if auth_method != 0x00:
                raise Exception(f"不支持的認證方法: 0x{auth_method:02x}")
            
            logger.info("SOCKS5 認證成功")
            return True
            
        except socket.timeout:
            logger.error("認證超時")
            raise
        except Exception as e:
            logger.error(f"認證失敗: {e}")
            raise

    def request(self, dst_addr: str, dst_port: int, timeout: int = 10, use_ssl: bool = False, udp: bool = False) -> bool:
        """發送 SOCKS5 請求
        
        Args:
            dst_addr: 目標地址（IPv4, IPv6或域名）
            dst_port: 目標端口
            timeout: 超時時間（秒）
            use_ssl: 是否使用SSL/TLS
            udp: 是否使用UDP模式
        
        Returns:
            bool: 連接是否成功
        """
        try:
            self.socket.settimeout(timeout)
            
            # 判斷地址類型
            try:
                # 嘗試解析為IPv6地址
                ipv6_addr = ipaddress.IPv6Address(dst_addr)
                atyp = 0x04  # IPv6
                addr_bytes = ipv6_addr.packed
                logger.debug(f"目標地址解析為IPv6: {dst_addr}")
            except ValueError:
                try:
                    # 嘗試解析為IPv4地址
                    ipv4_addr = ipaddress.IPv4Address(dst_addr)
                    atyp = 0x01  # IPv4
                    addr_bytes = ipv4_addr.packed
                    logger.debug(f"目標地址解析為IPv4: {dst_addr}")
                except ValueError:
                    # 既不是IPv4也不是IPv6, 視為域名
                    atyp = 0x03  # 域名
                    if len(dst_addr) > 255:
                        raise ValueError("域名長度超過255個字符")
                    addr_bytes = bytes([len(dst_addr)]) + dst_addr.encode()
                    logger.debug(f"目標地址解析為域名: {dst_addr}")
            
            # 構建請求
            command = 0x03 if udp else 0x01  # UDP = 0x03, CONNECT = 0x01
            header = struct.pack('!BBBB', 0x05, command, 0x00, atyp)
            port_bytes = struct.pack('!H', dst_port)
            request = header + addr_bytes + port_bytes
            
            logger.debug(f"SOCKS5請求類型: {'UDP' if udp else 'TCP'}, "
                        f"目標: {dst_addr}:{dst_port}")
            
            # 發送請求
            self._send_all(request)
            
            # 接收和解析響應
            response = self._recv_exact(4)
            version, rep, rsv, resp_atyp = struct.unpack('!BBBB', response)
            
            if version != 0x05:
                raise Exception("不是有效的 SOCKS5 協議")
            
            # 處理錯誤響應
            if rep != 0x00:
                error_msgs = {
                    0x01: "一般性失敗",
                    0x02: "規則集不允許連接",
                    0x03: "網絡不可達",
                    0x04: "主機不可達",
                    0x05: "連接被拒絕",
                    0x06: "TTL已過期",
                    0x07: "不支持的命令",
                    0x08: "不支持的地址類型"
                }
                error_msg = error_msgs.get(rep, "未知錯誤")
                raise Exception(f"連接請求被拒絕: {error_msg} (代碼: {rep})")
            
            # 讀取綁定地址和端口
            if resp_atyp == 0x01:  # IPv4
                addr = self._recv_exact(4)
                bound_addr = str(ipaddress.IPv4Address(addr))
            elif resp_atyp == 0x03:  # 域名
                addr_len = self._recv_exact(1)[0]
                addr = self._recv_exact(addr_len)
                bound_addr = addr.decode()
            elif resp_atyp == 0x04:  # IPv6
                addr = self._recv_exact(16)
                bound_addr = str(ipaddress.IPv6Address(addr))
            else:
                raise Exception(f"不支持的地址類型: {resp_atyp}")
                
            port = self._recv_exact(2)
            bound_port = struct.unpack('!H', port)[0]
            logger.debug(f"伺服器綁定地址: {bound_addr}:{bound_port}")
            
            # UDP模式特殊處理
            if udp:
                # 保存原始TCP socket用於保持UDP關聯
                self.tcp_socket = self.socket
                
                # 創建UDP socket
                # 判斷綁定地址類型來決定socket類型
                try:
                    ipaddress.IPv6Address(bound_addr)
                    self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                except ValueError:
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                self.socket.settimeout(timeout)
                
                # 綁定到任意本地端口
                if ':' in bound_addr:  # IPv6
                    self.socket.bind(('::', 0))
                else:  # IPv4 or 域名
                    self.socket.bind(('0.0.0.0', 0))
                
                local_addr, local_port = self.socket.getsockname()
                
                logger.debug(f"已創建UDP socket並綁定到 {local_addr}:{local_port}")
                
                # 記錄UDP關聯地址和端口，用於後續數據封裝
                self.udp_addr = bound_addr
                self.udp_port = bound_port
                
                logger.info(f"成功建立UDP關聯: 本地 {local_addr}:{local_port} -> "
                          f"代理 {bound_addr}:{bound_port}")
                          
                return True
                
            # TCP模式處理
            else:
                # 如果需要SSL/TLS
                if use_ssl:
                    logger.debug("開始SSL/TLS握手")
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    self.socket = context.wrap_socket(self.socket, server_hostname=dst_addr)
                
                logger.info(f"成功建立到 {dst_addr}:{dst_port} 的"
                          f"{'SSL/TLS ' if use_ssl else ' '}連接")
                return True
            
        except socket.timeout:
            logger.error(f"連接 {dst_addr}:{dst_port} 超時")
            raise
        except Exception as e:
            logger.error(f"建立連接失敗: {e}")
            raise
            
    def send_udp(self, data: bytes, dst_addr: str, dst_port: int) -> int:
        """發送UDP數據
        
        Args:
            data: 要發送的數據
            dst_addr: 目標地址
            dst_port: 目標端口
            
        Returns:
            int: 發送的字節數
        """
        if not hasattr(self, 'udp_addr'):
            raise Exception("未建立UDP關聯")
            
        try:
            # 構建UDP數據頭
            # +----+------+------+----------+----------+----------+
            # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA  |
            # +----+------+------+----------+----------+----------+
            # | 2  |  1   |  1   | Variable |    2     | Variable|
            # +----+------+------+----------+----------+----------+
            
            # 判斷地址類型
            try:
                # 嘗試解析為IPv6地址
                ipv6_addr = ipaddress.IPv6Address(dst_addr)
                atyp = 0x04  # IPv6
                addr_bytes = ipv6_addr.packed
            except ValueError:
                try:
                    # 嘗試解析為IPv4地址
                    ipv4_addr = ipaddress.IPv4Address(dst_addr)
                    atyp = 0x01  # IPv4
                    addr_bytes = ipv4_addr.packed
                except ValueError:
                    # 既不是IPv4也不是IPv6, 視為域名
                    atyp = 0x03  # 域名
                    if len(dst_addr) > 255:
                        raise ValueError("域名長度超過255個字符")
                    addr_bytes = bytes([len(dst_addr)]) + dst_addr.encode()
                
            # 構建UDP數據頭
            header = struct.pack('!HBB', 0, 0, atyp)  # RSV=0, FRAG=0
            port_bytes = struct.pack('!H', dst_port)
            udp_packet = header + addr_bytes + port_bytes + data
            
            # 發送到SOCKS5服務器的UDP轉發端口
            sent = self.socket.sendto(udp_packet, (self.udp_addr, self.udp_port))
            logger.debug(f"發送UDP數據: {len(data)}字節 -> {dst_addr}:{dst_port}")
            return sent
            
        except Exception as e:
            logger.error(f"發送UDP數據失敗: {e}")
            raise
            
    def recv_udp(self, buffer_size: int = 65507) -> Tuple[bytes, str, int]:
        """接收UDP數據
        
        Returns:
            Tuple[bytes, str, int]: (數據, 來源地址, 來源端口)
        """
        if not hasattr(self, 'udp_addr'):
            raise Exception("未建立UDP關聯")
            
        try:
            data, (addr, port) = self.socket.recvfrom(buffer_size)
            if addr != self.udp_addr or port != self.udp_port:
                raise Exception(f"收到非預期的UDP數據: {addr}:{port}")
                
            # 解析UDP數據頭
            if len(data) < 4:  # 最小頭部長度
                raise Exception("UDP數據太短")
                
            # 跳過RSV(2)和FRAG(1)
            atyp = data[3]
            offset = 4
            
            # 解析來源地址
            if atyp == 0x01:  # IPv4
                if len(data) < offset + 4:
                    raise Exception("IPv4地址不完整")
                src_addr = str(ipaddress.IPv4Address(data[offset:offset+4]))
                offset += 4
            elif atyp == 0x03:  # 域名
                if len(data) < offset + 1:
                    raise Exception("域名長度字段缺失")
                addr_len = data[offset]
                offset += 1
                if len(data) < offset + addr_len:
                    raise Exception("域名不完整")
                src_addr = data[offset:offset+addr_len].decode()
                offset += addr_len
            elif atyp == 0x04:  # IPv6
                if len(data) < offset + 16:
                    raise Exception("IPv6地址不完整")
                src_addr = str(ipaddress.IPv6Address(data[offset:offset+16]))
                offset += 16
            else:
                raise Exception(f"不支持的地址類型: {atyp}")
                
            # 解析來源端口
            if len(data) < offset + 2:
                raise Exception("端口號不完整")
            src_port = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            
            # 提取實際數據
            payload = data[offset:]
            
            logger.debug(f"收到UDP數據: {len(payload)}字節 <- {src_addr}:{src_port}")
            return payload, src_addr, src_port
            
        except Exception as e:
            logger.error(f"接收UDP數據失敗: {e}")
            raise

    def _recv_exact(self, n: int) -> bytes:
        """精確接收指定數量的字節"""
        data = bytearray()
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                raise Exception("連接已關閉")
            data.extend(chunk)
        return bytes(data)

    def _send_all(self, data: bytes) -> None:
        """確保完整發送所有數據"""
        total_sent = 0
        while total_sent < len(data):
            sent = self.socket.send(data[total_sent:])
            if sent == 0:
                raise Exception("連接已關閉")
            total_sent += sent
            logger.debug(f"已發送 {total_sent}/{len(data)} 字節")

    def close(self):
        """關閉所有連接並清理資源"""
        # 清理 UDP 相關資源
        if hasattr(self, 'tcp_socket'):
            try:
                self.tcp_socket.close()
                logger.debug("關閉UDP關聯的TCP連接")
            except Exception as e:
                logger.warning(f"關閉UDP關聯TCP連接失敗: {e}")
            self.tcp_socket = None
            
        # 清理UDP關聯信息
        if hasattr(self, 'udp_addr'):
            delattr(self, 'udp_addr')
            delattr(self, 'udp_port')
            logger.debug("清理UDP關聯信息")

        # 關閉主socket
        if self.socket:
            try:
                if isinstance(self.socket, ssl.SSLSocket):
                    try:
                        logger.debug("開始關閉SSL連接...")
                        # 發送SSL close_notify警報並關閉連接
                        self.socket.shutdown(socket.SHUT_RDWR)
                        logger.debug("SSL shutdown完成")
                    except ssl.SSLError as e:
                        if "application data after close notify" in str(e):
                            logger.debug("忽略預期的SSL關閉後數據")
                        else:
                            logger.warning(f"SSL關閉過程中出錯: {e}")
                    except Exception as e:
                        logger.warning(f"關閉SSL連接時出錯: {e}")

                # 關閉底層socket
                self.socket.close()
                logger.debug(f"已關閉{'UDP' if hasattr(self, 'udp_addr') else 'TCP'} socket")
                
            except Exception as e:
                logger.warning(f"關閉socket時出錯: {e}")
            finally:
                self.socket = None
                logger.info("完成SOCKS5連接清理")

class Socks5Connection:
    """表示通過SOCKS5代理建立的連接"""
    
    def __init__(self, client, target_host, target_port):
        self.client = client
        self.target_host = target_host
        self.target_port = target_port
    
    def send(self, data):
        """發送數據"""
        return self.client.socket.send(data)
    
    def recv(self, buffer_size=8192):
        """接收數據"""
        return self.client.socket.recv(buffer_size)
    
    def close(self):
        """關閉連接"""
        self.client.close()

    def settimeout(self, timeout):
        """設置超時"""
        if self.client.socket:
            self.client.socket.settimeout(timeout)

class ProxiedHttpClient:
    """通過SOCKS5代理發送HTTP請求的客戶端"""
    
    def __init__(self, proxy_host, proxy_port, timeout=30):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.timeout = timeout
        self.client = None
        self.connection = None
    
    def connect_to_target(self, url, use_ssl=None):
        """連接到目標URL"""
        try:
            # 解析URL
            parsed_url = urllib.parse.urlparse(url)
            scheme = parsed_url.scheme
            
            # 自動判斷是否使用SSL
            if use_ssl is None:
                use_ssl = (scheme == 'https')
            
            # 獲取主機和端口
            netloc = parsed_url.netloc
            if ':' in netloc:
                target_host, target_port_str = netloc.split(':', 1)
                target_port = int(target_port_str)
            else:
                target_host = netloc
                target_port = 443 if use_ssl else 80
            
            # 初始化SOCKS5客戶端
            self.client = Socks5Client(self.proxy_host, self.proxy_port)
            
            # 建立連接
            if not self.client.connect(timeout=self.timeout):
                raise Exception("無法連接到SOCKS5代理伺服器")
            
            if not self.client.auth():
                raise Exception("SOCKS5認證失敗")
            
            # 建立到目標的連接
            if not self.client.request(target_host, target_port, timeout=self.timeout, use_ssl=use_ssl):
                raise Exception(f"無法通過代理連接到目標: {target_host}:{target_port}")
            
            # 創建連接對象
            self.connection = Socks5Connection(self.client, target_host, target_port)
            return self.connection
        
        except Exception as e:
            logger.error(f"建立代理連接失敗: {e}")
            if self.client:
                self.client.close()
            raise
    
    def http_get(self, url, headers=None, range_header=None, stream_callback=None):
        """發送HTTP GET請求並返回回應"""
        try:
            # 解析URL
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path
            if not path:
                path = "/"
            if parsed_url.query:
                path += "?" + parsed_url.query
            
            # 連接到目標
            conn = self.connect_to_target(url)
            
            # 準備請求頭
            request_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Connection': 'close',
                'Host': conn.target_host
            }
            
            # 添加自定義頭
            if headers:
                request_headers.update(headers)
            
            # 添加範圍請求頭
            if range_header:
                request_headers['Range'] = range_header
            
            # 構建請求
            request = f"GET {path} HTTP/1.1\r\n"
            for key, value in request_headers.items():
                request += f"{key}: {value}\r\n"
            request += "\r\n"
            
            # 發送請求
            conn.send(request.encode())
            
            # 處理回應
            # 讀取狀態行
            status_line = b""
            while b"\r\n" not in status_line:
                chunk = conn.recv(1)
                if not chunk:
                    raise Exception("連接關閉，無法讀取狀態行")
                status_line += chunk
            
            status_text = status_line.decode().strip()
            parts = status_text.split(" ", 2)
            if len(parts) < 3:
                raise Exception(f"無效的HTTP狀態行: {status_text}")
            
            status_code = int(parts[1])
            status_msg = parts[2]
            
            # 讀取頭
            headers = {}
            header_data = b""
            while True:
                line = b""
                while b"\r\n" not in line:
                    chunk = conn.recv(1)
                    if not chunk:
                        raise Exception("連接關閉，無法讀取頭")
                    line += chunk
                
                header_data += line
                line = line.decode().strip()
                if line == "":  # 空行表示頭結束
                    break
                
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.strip()] = value.strip()
            
            # 處理主體數據
            if stream_callback:
                # 流式處理
                content = b""
                content_length = int(headers.get('Content-Length', -1))
                chunked = headers.get('Transfer-Encoding') == 'chunked'
                
                if chunked:
                    # 分塊編碼處理
                    remaining_chunk_size = 0
                    total_received = 0
                    
                    while True:
                        if remaining_chunk_size == 0:
                            # 讀取塊大小行
                            chunk_size_line = b""
                            while b"\r\n" not in chunk_size_line:
                                data = conn.recv(1)
                                if not data:
                                    break
                                chunk_size_line += data
                            
                            if not chunk_size_line:
                                break
                            
                            # 解析塊大小
                            chunk_size_hex = chunk_size_line.decode().split(";")[0].strip()
                            remaining_chunk_size = int(chunk_size_hex, 16)
                            
                            # 零大小的塊意味著結束
                            if remaining_chunk_size == 0:
                                # 讀取最後的 \r\n
                                conn.recv(2)
                                break
                        
                        # 讀取塊數據
                        bytes_to_read = min(8192, remaining_chunk_size)
                        data = conn.recv(bytes_to_read)
                        if not data:
                            break
                        
                        # 處理收到的數據
                        stream_callback(data, total_received, -1)
                        total_received += len(data)
                        remaining_chunk_size -= len(data)
                        
                        # 如果塊結束，讀取 \r\n
                        if remaining_chunk_size == 0:
                            conn.recv(2)
                
                elif content_length > 0:
                    # 已知內容長度
                    total_received = 0
                    
                    while total_received < content_length:
                        bytes_to_read = min(8192, content_length - total_received)
                        data = conn.recv(bytes_to_read)
                        if not data:
                            break
                        
                        # 處理收到的數據
                        stream_callback(data, total_received, content_length)
                        total_received += len(data)
                
                else:
                    # 未知內容長度，讀取直到連接關閉
                    total_received = 0
                    
                    while True:
                        data = conn.recv(8192)
                        if not data:
                            break
                        
                        # 處理收到的數據
                        stream_callback(data, total_received, -1)
                        total_received += len(data)
            
            else:
                # 一次性讀取所有數據
                content = b""
                while True:
                    data = conn.recv(8192)
                    if not data:
                        break
                    content += data
            
            # 關閉連接
            conn.close()
            
            return {
                'status_code': status_code,
                'status_msg': status_msg,
                'headers': headers,
                'content': content if not stream_callback else None
            }
        
        except Exception as e:
            logger.error(f"HTTP請求失敗: {e}")
            if self.connection:
                self.connection.close()
            raise

def test_udp_dns():
    """測試UDP DNS查詢"""
    client = Socks5Client()
    try:
        logger.info("\n=== 測試UDP DNS查詢 ===")
        
        if not client.connect() or not client.auth():
            logger.error("SOCKS5連接/認證失敗")
            return
            
        # 建立UDP關聯
        if not client.request(test_dns, 53, udp=True):
            logger.error("UDP關聯建立失敗")
            return
            
        # 構建簡單的DNS查詢
        query = struct.pack(
            '!HHHHHH',
            0x1234,     # Transaction ID
            0x0100,     # Flags: 標準查詢
            1, 0, 0, 0  # Questions:1, Answers:0, Auth:0, Additional:0
        )
        
        # 添加查詢域名 (www.google.com)
        for part in test_url.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00'  # 域名結束符
        
        # 添加查詢類型和類別 (A記錄, IN類)
        query += struct.pack('!HH', 1, 1)
        
        # 發送查詢並等待回應
        client.send_udp(query, test_dns, 53)
        data, addr, port = client.recv_udp()
        logger.info(f"收到DNS回應: {len(data)}字節 來自 {addr}:{port}")
        
    except Exception as e:
        logger.error(f"UDP DNS測試失敗: {e}")
    finally:
        client.close()

def test_ipv6():
    """測試IPv6連接"""
    try:
        logger.info("\n=== 測試IPv6連接 ===")
        ipv6_dns = "2001:4860:4860::8888"  # Google IPv6 DNS
        
        # 測試連接到IPv6 DNS服務器
        client = Socks5Client()
        if not client.connect() or not client.auth():
            logger.error("SOCKS5連接/認證失敗")
            return
        
        # 測試TCP連接到IPv6地址
        if client.request(ipv6_dns, 53):
            logger.info(f"成功連接到IPv6地址: {ipv6_dns}:53")
        
        client.close()
        
        # 測試UDP連接到IPv6地址
        client = Socks5Client()
        if client.connect() and client.auth() and client.request(ipv6_dns, 53, udp=True):
            # 構建DNS查詢（和上面相同）
            query = struct.pack(
                '!HHHHHH',
                0x5678,     # 不同的Transaction ID
                0x0100,     # Flags: 標準查詢
                1, 0, 0, 0  # Questions:1, Answers:0, Auth:0, Additional:0
            )
            
            # 添加查詢域名
            for part in test_url.split('.'):
                query += bytes([len(part)]) + part.encode()
            query += b'\x00'  # 域名結束符
            
            # AAAA記錄 (IPv6地址)
            query += struct.pack('!HH', 28, 1)
            
            # 發送查詢並等待回應
            client.send_udp(query, ipv6_dns, 53)
            data, addr, port = client.recv_udp()
            logger.info(f"收到IPv6 DNS回應: {len(data)}字節 來自 {addr}:{port}")
        
        client.close()
        logger.info("IPv6測試完成")
        
    except Exception as e:
        logger.error(f"IPv6測試失敗: {e}")

if __name__ == '__main__':
    try:
        # TCP連接測試
        logger.info("=== 測試TCP連接 ===")
        client = Socks5Client()
        client.connect()
        client.auth()
        client.request(test_dns, 53)
        client.close()

        # UDP DNS測試
        test_udp_dns()
        
        # IPv6 連接測試
        test_ipv6()
        
        # HTTPS連接測試
        logger.info("\n=== 測試HTTPS連接 ===")
        client = Socks5Client()
        client.connect()
        client.auth()
        test_ssl = client.request(test_url, 443, use_ssl=True)
        test_ssl = client.socket.send(b'GET / HTTP/1.1\r\nHost: ' + test_url.encode() + b'\r\n\r\n')
        test_ssl = client.socket.recv(4096)
        print(test_ssl.decode())
        client.close()
        
        print("測試完成")

    except Exception as e:
        logger.error(f"測試失敗: {e}")
