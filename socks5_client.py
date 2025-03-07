import socket
import struct
import logging
import ssl
from typing import Union, Tuple

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Socks5Client:
    def __init__(self, server_addr='192.168.1.102', server_port=30678):
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
            dst_addr: 目標地址（IP或域名）
            dst_port: 目標端口
            timeout: 超時時間（秒）
            use_ssl: 是否使用SSL/TLS
            udp: 是否使用UDP模式
        
        Returns:
            bool: 連接是否成功
        """
        try:
            self.socket.settimeout(timeout)
            
            # 判斷是IP還是域名
            try:
                socket.inet_aton(dst_addr)  # 嘗試轉換為IP
                atyp = 0x01  # IPv4
                addr_bytes = socket.inet_aton(dst_addr)
            except socket.error:
                atyp = 0x03  # 域名
                addr_bytes = bytes([len(dst_addr)]) + dst_addr.encode()
            
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
                bound_addr = socket.inet_ntoa(addr)
            elif resp_atyp == 0x03:  # 域名
                addr_len = self._recv_exact(1)[0]
                addr = self._recv_exact(addr_len)
                bound_addr = addr.decode()
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
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.settimeout(timeout)
                
                # 綁定到任意本地端口
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
                socket.inet_aton(dst_addr)  # 嘗試轉換為IP
                atyp = 0x01  # IPv4
                addr_bytes = socket.inet_aton(dst_addr)
            except socket.error:
                atyp = 0x03  # 域名
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
                src_addr = socket.inet_ntoa(data[offset:offset+4])
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

def test_udp_dns():
    """測試UDP DNS查詢"""
    client = Socks5Client()
    try:
        logger.info("\n=== 測試UDP DNS查詢 ===")
        
        if not client.connect() or not client.auth():
            logger.error("SOCKS5連接/認證失敗")
            return
            
        # 建立UDP關聯
        if not client.request('8.8.8.8', 53, udp=True):
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
        for part in 'www.google.com'.split('.'):
            query += bytes([len(part)]) + part.encode()
        query += b'\x00'  # 域名結束符
        
        # 添加查詢類型和類別 (A記錄, IN類)
        query += struct.pack('!HH', 1, 1)
        
        # 發送查詢並等待回應
        client.send_udp(query, '8.8.8.8', 53)
        data, addr, port = client.recv_udp()
        logger.info(f"收到DNS回應: {len(data)}字節 來自 {addr}:{port}")
        
    except Exception as e:
        logger.error(f"UDP DNS測試失敗: {e}")
    finally:
        client.close()

if __name__ == '__main__':
    try:
        # TCP連接測試
        logger.info("=== 測試TCP連接 ===")
        client = Socks5Client()
        client.connect()
        client.auth()
        client.request('8.8.8.8', 53)
        client.close()

        # HTTPS連接測試
        logger.info("\n=== 測試HTTPS連接 ===")
        client = Socks5Client()
        client.connect()
        client.auth()
        test_ssl = client.request('www.google.com', 443, use_ssl=True)
        test_ssl = client.socket.send(b'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n')
        test_ssl = client.socket.recv(4096)
        print(test_ssl.decode())
        client.close()
        
        # UDP DNS測試
        test_udp_dns()
        
    except Exception as e:
        logger.error(f"測試失敗: {e}")