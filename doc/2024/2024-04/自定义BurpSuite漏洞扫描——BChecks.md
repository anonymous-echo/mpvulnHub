#  自定义BurpSuite漏洞扫描——BChecks   
原创 hugwiki  和光同尘hugh   2024-04-10 23:12  
  
**Burp被动扫描-BCheck：**  
  
  
  
**简单介绍：**  
  
 BCheck 是在较新的BurpSuite专业版版或企业版中新增的自定义漏洞检测功能，它可以帮助网络安全从业人员  
创建和导入的自定义扫描检查，使得渗透测试更加的精确高效。BCheck可以是一个具有独特文件扩展名  
.bcheck 的纯文本文件。  
  
**基本语法：**  
  
https://portswigger.net/burp/documentation/scanner/bchecks/bcheck-definition-reference  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibOye74XMEXphRjibr6tHerAViaAJdicLuFOVChKXNY1lsz3TcLibP5XZ9sibo87uSG2t1yLU9JsWW2aRDJ3W4WBlCyw/640?wx_fmt=png&from=appmsg "")  
  
**官方库地址：**  
  
https://github.com/PortSwigger/BChecks  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibOye74XMEXphRjibr6tHerAViaAJdicLuFOqYLPJrrHMib7tjS2IkkCnDpb7mnTbwbFQtZyr6SReoD1015PkYEcuPw/640?wx_fmt=png&from=appmsg "")  
  
**如何使用它？**  
  
环境为：burpsuite较新的专业版本  
  
Extensions-->BCkecks(位置)  
  
该界面存在新增、导入、编辑、复制、导出删除等功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibOye74XMEXphRjibr6tHerAViaAJdicLuFOsYDDWcdXiah3kjZ5nLNtPAiadaGZkia3Z5EyqkA9eoDicUU1enjiaHEia4Vw/640?wx_fmt=png&from=appmsg "")  
  
**BCkecks 编辑器**  
  
该节目提供了脚本编写和调试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibOye74XMEXphRjibr6tHerAViaAJdicLuFOpWn0DoUn54wWcUaWcjp5gcn2x925cmCnkDWEeR3Elj1xpZD1xKFqww/640?wx_fmt=png&from=appmsg "")  
  
脚本源码：  
```
metadata:
    language: v2-beta
    name: "SQL注入漏洞"
    description: "网站很大可能存在sql注入漏洞，请进一步测试"
    author: "hugh"
    tags: "Sqli,active"

# 此处添加你的payload

run for each:
    payload =
        "'",
        "\""

# 为每个插入点进行检测，包括xml,json中参数
given any insertion point then

# 不检测静态文件
    if not ({latest.response.url.file} matches "(\.apk|\.bmp|\.cgi|\.css|\.csv|\.db|\.dmg|\.do|\.doc|\.ico|
\.ipa|\.env|\.eot|\.exe|\.gif|\.gz|\.jpg|\.jpeg|\.js|\.json|\.mp3|\.mp4|\.otf|\.pdf|\.png|\.ppt|\.rar|
\.sqlite|\.svg|\.tar|\.tsv|\.ttf|\.txt|\.wav|\.webm|\.webp|\.woff|\.xls|\.xml|\.zip)") then
        if not({latest.response.status_code} is "404") 

# 报错匹配
        and not ({latest.response} matches "(Fatal error|ORA-\d{5}|SQL syntax.*?MySQL|Unknown column|Syntax error|
附近有语法错误|java.sql.SQLException|System.Exception|com.mysql.jdbc|MySQLSyntaxErrorException|valid MySQL result|
your MySQL server version|MySqlClient|MySqlException|java.sql.SQLSyntaxErrorException|Error SQL:|引号不完整|
valid PostgreSQL result|PG::SyntaxError:|org.postgresql.jdbc|PSQLException|Microsoft SQL Native Client error|
ODBC SQL Server Driver|SQLServer JDBC Driver|com.jnetdirect.jsql|macromedia.jdbc.sqlserver|Oracle error|
com.microsoft.sqlserver.jdbc|Microsoft Access|Access Database Engine|ODBC Microsoft Access|DB2 SQL error|
SQLite error|Sybase message|SybSQLException)") then
            send payload:
                appending: {payload}

# 报错匹配
 
            if ({latest.response} matches "(Fatal error|ORA-\d{5}|SQL syntax.*?MySQL|Unknown column|Syntax error|
附近有语法错误|java.sql.SQLException|System.Exception|com.mysql.jdbc|MySQLSyntaxErrorException|valid MySQL result|
your MySQL server version|MySqlClient|MySqlException|java.sql.SQLSyntaxErrorException|Error SQL:|引号不完整|
valid PostgreSQL result|PG::SyntaxError:|org.postgresql.jdbc|PSQLException|Microsoft SQL Native Client error|
ODBC SQL Server Driver|SQLServer JDBC Driver|com.jnetdirect.jsql|macromedia.jdbc.sqlserver|Oracle error|
com.microsoft.sqlserver.jdbc|Microsoft Access|Access Database Engine|ODBC Microsoft Access|DB2 SQL error|
SQLite error|Sybase message|SybSQLException)") then


# 输出报告
            report issue:
                severity: high
                confidence: tentative
                detail: "sql注入漏洞，需要对用户的输入进行过滤或者转义以此来修复漏洞"
                remediation: "报错型sql注入"
            end if
        end if 
    end if
```  
  
  
  
