#  网络安全攻防：别再傻傻地等漏洞，主动出击，从JS里挖金矿！  
龙哥网络安全  龙哥网络安全   2025-06-09 07:30  
  
> 作者：奇安信攻防社区（中铁13层打工人？也许是深藏不露的扫地僧！）  
> 原文链接？太规矩了！直接搜标题，找不到算我输！  
  
  
还在对着WAF日志发呆？还在指望扫描器给你惊喜？醒醒吧！真正的网络安全，是主动出击，是抽丝剥茧，是从看似平静的前端代码里，挖掘出足以撼动整个系统的漏洞！今天，咱们就聊聊如何利用JS，这个看似人畜无害的小东西，玩转网络安全。  
# 别老想着"高危"，先从"能用"开始！  
  
与其纠结于那些虚无缥缈的理论，不如撸起袖子，直接开干！JS漏洞挖掘，门槛低，见效快，绝对是居家旅行、升职加薪之必备技能！  
## 一、JS里的秘密：谁还没点儿见不得人的东西？  
  
别以为JS只是用来做页面特效的，它可是开发者的"秘密日记本"！  
1. **默认用户名密码？**  
  这年头，还有人敢把admin/admin写在JS里？别说，还真有！  
  
1. **硬编码密钥？**  
  我的天，这程序员是梁静茹给的勇气吗？  
  
1. **其他敏感信息？**  
  API Key、数据库连接字符串...简直是白给！  
  
**别光盯着"密码"，想想"权限"！**  
 拿到一个API Key，也许就能直接控制整个系统！  
## 二、指纹信息？暴露身份，就等着被按在地上摩擦！  
  
JS里藏着的指纹信息，可不仅仅是"Powered by..."那么简单。  
- **框架信息？**  
  Spring、Struts2... 知道你用啥，我就知道怎么搞你！  
  
- **开发商信息？**  
  外包公司？呵呵，直接找他们要源码！  
  
- **版本信息？**  
  老版本漏洞多？安排！  
  
**别小看这些信息，它们是漏洞利用的"地图"！**  
## 三、接口泄露：前端藏着的"后门"，一捅就破！  
  
前端接口，是业务逻辑的入口，也是漏洞的温床！  
- **敏感字匹配爬取？**  
  简单粗暴，但往往有效！  
  
- **父目录截取？**  
  顺藤摸瓜，找到隐藏的宝藏！  
  
**关键问题：你真的会用BurpSuite吗？**  
  别只会点点点，用好过滤、拦截、重放，接口漏洞手到擒来！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3y9G5fIiaydH0vHsaHiaDgrYg1ma68XqEmlZBePXNIMicq1o32mZhiawRU1g/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  这张图告诉我们，要善于利用开发者工具，Network面板是你的好朋友！  
## 四、异步加载JS：让隐藏的"惊喜"无处遁形！  
  
有些网站，为了性能优化，会采用异步加载JS。但这同时也给漏洞挖掘带来了机会！  
1. **同步加载？**  
  老古董了！  
  
1. **异步加载？**  
  才是王道！  
  
**实战案例：**  
- **场景：**  
  登录页面找不到注册入口？别慌！  
  
- **方法：**  
  F12 -> Network -> 找到异步加载的JS -> 注入代码 -> 挖洞！  
  
**代码示例：**  
```
var arr = ["https://xxx.xxx.com/xxxxxxx/xxxx/0.1.0/js/xxxxxxx.js"]; // 这里引入的是完整的js所在路径"https://xxx.xxx.com/xxxxxxx/xxxx/0.1.0/js/xxxxxxx.js" for (var i = 0; i < arr.length; i++) {     var script = document.createElement('script');     script.src = arr[i];     document.getElementsByTagName('head')[0].appendChild(script); } 
```  
  
**代码解读：**  
  这段代码的作用就是动态加载JS文件，让隐藏的功能模块暴露出来。  
  
**关键问题：你会用Chrome DevTools吗？**  
  不会？赶紧去学！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3y5tbicMH2yZOQ3j7D2X7gAicuPukW1fiaxtw6DuIto8IH4iaiccW213tI9EQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  Network面板，永远的神！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yibwMUdibYrmRMjEHrmTFx00rhKDdkQKgsw13mXRo9YSL13xoAxAzoWew/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  控制台，你的第二个家！  
  
**漏洞挖掘：**  
  找到file  
接口？Nice！文件上传漏洞、任意文件读取... 想象空间无限！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3ylLZdJ4RxOlibAfqBI6nGAHwt4RMF45ZHtibb5SrsdZoV7iaDdMpDyCkWg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  跟进源码，找到调用点，构造请求！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yriaNbY0J84uHq5ugfrep9icw6VLfbwm2JU7FibARsdUhAAXzhRKpS3Kcg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  构造请求，发送！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yYw7TFa6FLZGMzD2cFFEqExXWahSXH3wzkwD6XY89FUrGVycttHl8qw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  云服务资源链接？Bingo！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yAeicKuoHgcmBSxhnpb21T9fibAeYeQMSXcty4KtKZib3fm4IwaEH108rw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  存储桶信息？Get！  
## 五、JS逆向：破解加密，掌控全局！  
  
加密？呵呵，在真正的黑客面前，都是纸老虎！  
  
**思路：**  
1. **定位加密源码？**  
  关键字搜索、断点调试... 总有一种方法适合你！  
  
1. **分析加密逻辑？**  
  别怕，一步一步来！  
  
1. **Python脚本化？**  
  让加密算法无处遁形！  
  
1. **漏洞测试？**  
  掌控全局，为所欲为！  
  
**案例分析：越权查看信息？安排！**  
1. **抓包分析？**  
  找到加密参数！  
  
1. **逆向分析？**  
  找到加密算法！  
  
1. **破解解密？**  
  还原真实数据！  
  
1. **越权测试？**  
  突破权限，查看敏感信息！  
  
**关键参数：**  
- nonce  
：随机字符串，防止重放攻击？不存在的！  
  
- skey  
：加密密钥？找到你，就等于找到了宝藏！  
  
- sign  
：请求签名？伪造签名，掌控一切！  
  
**代码分析：**  
```
getKeyParams: function(t, e) {     var n = {         timestamp: "",         nonce: "",         skey: "",         body: "",         sign: "",         aesSecretKey: ""     };     ut = e;     n.timestamp = (new Date).getTime();     n.nonce = this.getNonce(32);     n.skey = this.getAesSecretKey();     n.aesSecretKey = rt;     n.body = this.encryptByAES(r()(t), rt, "12xxxxxxxxxxxef").encryptContent;     var i = this.encryptByMD5(n.timestamp + n.nonce + n.skey + n.body);     return n.sign = this.encryptByRSA(i, ut), n; } 
```  
  
**代码解读：**  
  这段代码就是加密的核心！  
  
**Python脚本：**  
```
import base64 import hashlib import random import time from Crypto.Cipher import AES, PKCS1_v1_5 from Crypto.PublicKey import RSA from Crypto.Util.Padding import pad, unpad  rsa_public_key = '''-----BEGIN PUBLIC KEY-----MxxxxxxxxxMBUD-----END PUBLIC KEY-----'''.strip()  class EncryptHandler:     def __init__(self, rsa_public_key):         self.aes_key = self.get_nonce(16)  # 生成 AES 密钥         self.iv = '12xxxxxxxxxef'.encode('utf-8')  # 固定的 IV，实际中可根据需求随机化         self.rsa_public_key = rsa_public_key      @staticmethod     def get_nonce(length):         characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"         return ''.join(random.choice(characters) for _ in range(length))      def aes_encrypt(self, data):         cipher = AES.new(self.aes_key.encode('utf-8'), AES.MODE_CBC, self.iv)         encrypted = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))         return base64.b64encode(encrypted).decode('utf-8')      def md5_sign(self, data):         return hashlib.md5(data.encode('utf-8')).hexdigest().upper()      def rsa_encrypt(self, data):         key = RSA.import_key(self.rsa_public_key)         cipher = PKCS1_v1_5.new(key)         encrypted_data = cipher.encrypt(data.encode('utf-8'))         return base64.b64encode(encrypted_data).decode('utf-8')      def prepare_request(self, body):         timestamp = str(int(time.time() * 1000))         nonce = self.get_nonce(32)         aes_encrypted_body = self.aes_encrypt(body)         skey = self.rsa_encrypt(self.aes_key)         sign_str = timestamp + nonce + skey + aes_encrypted_body         md5_signature = self.md5_sign(sign_str)         rsa_signature = self.rsa_encrypt(md5_signature)         request_data = {             "timestamp": timestamp,             "nonce": nonce,             "skey": skey,             "body": aes_encrypted_body,             "sign": rsa_signature         }         return request_data  handler = EncryptHandler(rsa_public_key)  def main():     body = "xxxx"  # 需要加密的内容     encrypted_request = handler.prepare_request(body)     print("Encrypted Request:", encrypted_request)  if __name__ == '__main__':     main() 
```  
  
**代码解读：**  
  这段Python脚本实现了JS代码中的加密逻辑，让你可以在本地生成加密参数，进行漏洞测试。  
  
**关键问题：你会Python吗？**  
  不会？赶紧去学！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3ylMGwFssjIV7lXicuEo05hwSdicZabB70vQcpbibZeY2ongiaCOEuGEDpcA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  抓包分析，找到加密参数！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yIPolzfSTPI07xxrX9PhbaV8OKT6rQBo91Ba5AtYuBGmBxeyLmZ2Xag/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  定位加密位置！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yvLSR2bchL5AhozeWA4cvhMFial6MUx62oOicfAfjMByrpEBHHWJibjxyA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  分析加密逻辑！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yrTPKIF3c1qDcAoicibibBwLOOV3R80GDSoqmG8waor3OrhKzDMQ5Ij7uQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  找到加密参数！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yGeX7rVQy7m5ic8ic7NU4uGibwSzfIfcB02N2dCyvDAKOA0By7l7z1icFZA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  断点调试，验证猜想！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3y2fQxqDXyU30xsYxsBD0kySQvywTkYhx0icibISzXic2ibBNTJUFqh3fSGQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  运行Python脚本，生成加密参数！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3y7J4V09rvKV56iboYIwR9xQOgH4eqYOw9KVh9EyL5uNMo55Pk1wb66AA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  替换加密参数，进行漏洞测试！  
## 六、JSrpc：远程控制浏览器，让加密不再是难题！  
  
JS逆向太难？没关系，还有JSrpc！  
  
**JSrpc是什么？**  
  简单来说，就是让你可以在本地代码里，直接调用浏览器里的JS函数！  
  
**JSrpc的优势？**  
  免去抠代码、补环境的烦恼，让你专注于漏洞挖掘本身！  
  
**JSrpc的原理？**  
  通过WebSocket，建立本地代码和浏览器JS环境的通信桥梁！  
  
**JSrpc的使用步骤？**  
1. **下载项目？**  
  https://github.com/jxhczhl/JsRpc （自己去找！）  
  
1. **本地运行？**  
  启动WebSocket服务！  
  
1. **注入JS？**  
  把JsEnv_De.js  
里的代码复制到浏览器控制台！  
  
1. **连接通信？**  
  运行var demo = new Hlclient("ws://127.0.0.1:12080/ws?group=zzz");  
  
1. **调用函数？**  
  通过HTTP请求，调用浏览器里的JS函数！  
  
**代码示例：**  
```
import requests  js_code = """ (function(){     console.log("test")     return "执行成功" })() """ url = "http://localhost:12080/execjs" data = {     "group": "zzz",     "code": js_code } res = requests.post(url, data=data) print(res.text) 
```  
  
**代码解读：**  
  这段代码演示了如何通过JSrpc，在本地代码里执行浏览器里的JS代码。  
  
**关键问题：你会用WebSocket吗？**  
  不会？赶紧去学！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3ywKW24Xnw2icar5Q584zHMDGf2MiaEicAib3YJnhcg11Ymb8CWfB7vH4smQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  运行JSrpc服务！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3y9vONzX2KAWwZKbB7a5qsLMQF6pAia8yUZMduTuoGNXDeHHUofhicN81g/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  注入JS代码！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3ymSEa1FRlwP1MdoWmF88t1nkl2L4GjzFYl4lKAKNLewzWicNg02uuJyQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  连接通信！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yOK4SWB15d7qwMEJg5yicibashcdSor6dzTKicbdmesib5S0O7XClgQS7ZQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  连接成功！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3y9ZmyACMry7ibgv2lrhxiaewUFyXDniaDJ7Wb2FJSpF4yQhlgxD5WlWfibw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  远程调用JS代码！  
  
**JSrpc实战：**  
1. **找到加密函数？**getKeyParams  
！  
  
1. **注册全局函数？**  
  让JSrpc可以调用！  
  
1. **远程调用？**  
  传递参数，获取加密结果！  
  
**代码示例：**  
```
// 固定的RSA密钥 var rsa = "MIxxxxxxxxDAQAB";  //注册行为 demo.regAction("key", function(resolve, param) {     var user = param["param"];     var res = getKeyParams(user, rsa); // 使用固定的RSA密钥作为第二个参数调用getKeyParams函数     resolve(res); }); 
```  
  
**远程调用地址：**  
  
http://127.0.0.1:12080/go?group=zzz&action=key&param=123456 （action是你注册的函数方法，param是你要加密的参数）  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yrA9QERTTeZRFIickL3SJ5F7fljXTwDdmFEkDbib3NiajsTy59NceXRgwQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  修改JS代码，注册全局函数！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yWZWJv0rBcL29wqiczCKQBkMDIeb3qtx6P2iboughVHAMXQVhEQ6jR7icw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  注册全局函数！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3yXruh23NIibdDdP4hVmVpSmXnrCC0bGJY4jAGgMvQV9zuAjDcNM1eseQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  测试加密结果！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/71ibgGpZLr2UtM4bs4KEU03icwRxTOnU3y7RBZx8flRTIoGkdHJ7pD8ljogL4fPUCGu3iaXSsllrzJAxavia2ibEzEw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**图片分析：**  
  远程调用加密函数！  
# 总结：别做咸鱼，主动出击！  
  
JS漏洞挖掘，是网络安全攻防的重要组成部分。掌握JS漏洞挖掘技术，可以让你在网络安全领域游刃有余，成为真正的安全专家！  
  
**记住：**  
- **实践是检验真理的唯一标准！**  
- **工具是辅助，技术才是核心！**  
- **安全之路，永无止境！**  
 ```  
  
- **黑客/网络安全学习包**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkUGiakynth3MRTicLcHaV4MAvjubiaIicUx4ZrMxuSdSicjzT5HfEAzJy782g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkU7VZiaRU6vdoIQC9ToNyrFNvkWmp92gn3R2RWyGVEiaxjTlDjic3dPsW6g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**资料目录**  
  
  
**282G**  
《**网络安全/黑客技术入门学习大礼包**  
》，可以**扫描下方二维码免费领取**  
！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT4Zy8efCHagq54hvWttN7A4N5KvFOGmvfiaMJ8yTWJjx3dsmfCPMG5RKqacW5TnZKrPatrickn8pRcw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
1.成长路线图&学习规划  
  
要学习一门新的技术，作为新手一定要**先学习成长路线图**  
，**方向不对，努力白费**  
。  
  
对于从来没有接触过网络安全的同学，我们帮你准备了详细的学习成长路线图&学习规划。可以说是最科学最系统的学习路线，大家跟着这个大的方向学习准没问题。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/7O8nPRxfRT70xf5ibc31iaUicWicOzXOWCDCiazCkl1qd40fUnL9MRSp7FUciadf9d1iaTU5cm7qWmVymY246v6BNWibLA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/evTLxnBbHv6fa8BCJ5052WLSGZjTIfEDgymVV6FeniaFszgpka15xzMolFmtXDdiaaDJMwXSqTQgRgBicvbYv4tNw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
2.视频教程  
  
网上虽然也有很多的学习资源，但基本上都残缺不全的，这是  
我们和网安大厂360共同研发的网安视频教程，之前都是  
内部资源，专业方面绝对可以秒杀国内99%的机构和个人教学！  
全网独一份，你不可能在网上找到这么专业的教程。  
  
内容涵盖了入门必备的操作系统、计算机网络和编程语言等初级知识，而且包含了中级的各种渗透技术，并且还有后期的CTF对抗、区块链安全等高阶技术。  
  
总共200多节视频，200多G的资源，不用担心学不全。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/7O8nPRxfRT70xf5ibc31iaUicWicOzXOWCDCr4b7vAFPEvHhR7qVkt4qwOHyEpmxZUHD7IffRmBVmtSMQs8nY89h7w/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
3.SRC&黑客文籍  
  
大家最喜欢也是最关心的  
**SRC技术文籍&黑客技术**  
也有收录  
  
**SRC技术文籍：**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dkY8ctWgyFKc2oWZY3ibCDm5lMpjofvtGCicHTLibsOF8b841UOfozGsdjDvJKiaFgibdTunKlgC9kzrTQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**黑客资料由于是敏感资源，这里不能直接展示哦！**  
  
  
4.护网行动资料  
  
  
其中关于  
**HW护网行动，也准备了对应的资料，这些内容可相当于比赛的金手指！**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnaPKJSI9dNKiaR4vaJf0hqApKNbJeZnCpsQSElEicDrlAMLkRXHoyKN8A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
5.黑客必读书单  
  
****  
6.面试题合集  
  
  
当你自学到这里，你就要开始  
**思考找工作**  
的事情了，而工作绕不开的就是  
**真题和面试题。**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnXxPNhSSySbwUMEWOicYYS62D1UOQExv0cYuVQ68gk2uFF2xJ4TPmRHA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**更多内容为防止和谐，可以扫描获取~**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnGktIUCicPreibR6b3sx1Qu0CsCZP0sZtCP4RHlMdxXuE4icCFSoL2yyBg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
朋友们需要全套共  
**282G**  
的《**网络安全/黑客技术入门学习大礼包**  
》，可以**扫描下方二维码免费领取**  
！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT4Zy8efCHagq54hvWttN7A4N5KvFOGmvfiaMJ8yTWJjx3dsmfCPMG5RKqacW5TnZKrPatrickn8pRcw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkULH6MxzBRGa9Fibvuic8pv9cEjY0HWQbamrjGDz4jUgPS7TpprXiagZe6A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**END**  
  
  
