> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIwMzU0ODczOA==&mid=2247487084&idx=3&sn=26069ba9675bfc29f3231028f1704b45

#  EXP公开 | Windows Server 2025 Golden dMSA高危：跨域持久控制  
原创 黎多鱼  黎多鱼   2025-07-18 01:01  
  
近日，网络安全研究机构 Semperis 披露了 Windows Server 2025 中的一项重大安全问题：  
新引入的委托托管服务账户（dMSA）存在严重设计缺陷，可能被利用实施“Golden dMSA 攻击”，实现跨域横向移动和对企业网络的长期持续访问。  
  
![image](https://mmbiz.qpic.cn/mmbiz_png/RSIvXfbOBpxcsK415uZqic7pF39J59HOsSialiar56S6Tian42sib7ibhCOYX5svmYPtlRUKkEFwH06QFPUtoNsLtoXg/640?wx_fmt=png&from=appmsg "")  
## 事件核心：从单点漏洞到全域威胁  
  
dMSA 是 Windows Server 2025 推出的新功能，旨在通过“机器身份绑定+自动密码轮换”提升服务账户安全性，抵御传统凭据攻击。但 Semperis 研究发现，其与组托管服务账户（gMSA）共享基于密钥分发服务（KDS）根密钥的加密架构，这一设计缺陷让攻击者有了可乘之机。  
  
Golden dMSA 攻击的关键在于：**一旦攻击者获取 KDS 根密钥（通常需通过域控制器高权限访问），无需持续入侵域控制器，即可离线生成所有 dMSA 和 gMSA 的有效密码**  
。这意味着，一次局部入侵可能演变为全森林范围的持久控制——跨域渗透、全域凭据收集、长期访问成为可能。![image](https://mmbiz.qpic.cn/mmbiz_jpg/RSIvXfbOBpxcsK415uZqic7pF39J59HOsNmXE0RrAY14nqRL7aGWRHQM9ck8HdIGqWbsicbUskvpiaThSbiaibc1PIA/640?wx_fmt=jpeg "")  
  
## 攻击影响：低复杂度，高风险  
  
该攻击被评定为“中等风险”，但影响范围极广：  
- 跨域无边界：从森林中任一域获取 KDS 根密钥，可攻陷所有域的 dMSA 账户；  
  
- 持久化极强：KDS 根密钥无过期机制，且系统优先使用最旧密钥，可能形成数年“后门”；  
  
- 绕过防护：完全无视 Credential Guard 等安全机制，直接生成密码哈希而非窃取凭据。  
  
Semperis 指出，这一攻击将单个域的 KDS 根密钥泄露，转化为“森林级持久后门”，对企业 Active Directory 安全构成严重威胁。  
## 关键信息：研究与工具披露  
- 该漏洞由 Semperis 安全研究员 Adi Malyanker 发现，于 2025 年 5 月 27 日向微软披露；  
  
- 微软回应称“相关功能从未旨在防止域控制器被入侵”；  
  
- Semperis 已发布开源概念验证工具（PoC）“GoldenDMSA”，演示攻击流程。  
  
## 更多阅读  
  
技术原理深度研究：
```


```

  
  

```
https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/
```

  
  
EXP工具获取：
```


```

  
  

```
https://github.com/Semperis/GoldenDMSA?tab=readme-ov-file
```

  
  
**若上述链接无法访问**  
，可关注本微信公众号，回复关键词   
1153 领取备用资源。  
  
  
**·END·**  
  
关注我  
，每天了解一点国内外安全威胁情报、实战技巧，不走迷路。  
  
我是黎多鱼，聚焦安全威胁情报、行业资讯。  
  
  
