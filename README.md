# SOCKS5 代理服務器

這是一個基於Python實現的高性能SOCKS5代理服務器，支持IPv4/IPv6雙棧模式、用戶驗證、TCP/UDP轉發等功能。

## 特點

- 🌐 支持IPv4/IPv6雙棧模式
- 🔐 可選的用戶名密碼驗證
- 🚀 支持TCP和UDP協議
- ⚙️ 可配置的服務器參數
- 📝 內建日誌系統
- 🔄 使用非阻塞IO提升性能
- 💾 支持日誌文件輪轉

## 系統要求

- Python 3.6+
- 支持IPv6的操作系統（可選，僅IPv4模式不需要）

## 安裝

1. 克隆儲存庫：
```bash
git clone https://github.com/yourusername/socks5-server.git
cd socks5-server
```

2. 配置服務器參數：
創建或編輯 `s5.ini` 文件：
```ini
[Server]
Port = 30678
IPv4_Bind = 0.0.0.0
IPv6_Bind = ::

[Authentication]
EnableValidation = false
Username = admin
Password = 1234

[Logging]
EnableLogging = true
LogLevel = DEBUG
```

## 配置說明

### Server 部分
- `Port`: 服務器監聽端口（默認：30678）
- `IPv4_Bind`: IPv4綁定地址（默認：0.0.0.0）
- `IPv6_Bind`: IPv6綁定地址（默認：::）

### Authentication 部分
- `EnableValidation`: 是否啟用驗證（true/false）
- `Username`: 驗證用戶名
- `Password`: 驗證密碼

### Logging 部分
- `EnableLogging`: 是否啟用日誌（true/false）
- `LogLevel`: 日誌級別（DEBUG/INFO/WARNING/ERROR）

## 使用方法

1. 直接運行：
```bash
python s5.py
```

2. 使用執行檔運行（如果有提供）：
```bash
./s5
```

服務器啟動後，會在控制台顯示運行狀態和綁定地址。

## 連接測試

可以使用以下方法測試服務器是否正常運行：

1. 使用 curl 測試：
```bash
curl --socks5 127.0.0.1:30678 http://example.com
```

2. 使用提供的測試腳本：
```bash
python testsocks5.bat
```
需要驗證的話
python testsocks5.py -s HOST_IP:30678 -u Username -p Password
※ 請將IP設置為本機在局域網路或網際網路上的IP以確保UDP功能正常運行

## 性能優化

服務器使用了多項性能優化措施：

- 使用 `ThreadingMixIn` 實現多線程處理
- UDP 轉發使用非阻塞 IO
- 優化的緩衝區大小設置
- 高效的數據包處理機制

## 安全建議

1. 在生產環境中建議：
   - 啟用用戶驗證
   - 設置強密碼
   - 限制監聽地址
   - 使用防火牆限制訪問

2. 開啟日誌記錄以便監控和排查問題

## 日誌文件

- 日誌文件位置：`socks5.log`
- 支持日誌輪轉，默認單個文件最大 1MB
- 保留最近 5 個日誌文件

## 協議說明

本項目實現了 [RFC 1928](https://tools.ietf.org/html/rfc1928) 定義的 SOCKS5 協議，包括：

- 協議版本協商
- 用戶驗證 ([RFC 1929](https://tools.ietf.org/html/rfc1929))
- TCP 連接轉發
- UDP 協議支持
- 異常處理和錯誤碼

## 許可證

MIT License

## 贊助

如果您覺得這個項目對您有幫助，歡迎給個 Star ⭐️