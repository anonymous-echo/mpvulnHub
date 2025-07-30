> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070394&idx=4&sn=aeed87696ea8fe6444b8b1cb9444bf8e

#  【安全圈】Open VSX Registry 爆出严重漏洞，数百万开发者面临供应链攻击风险  
 安全圈   2025-06-27 11:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgYHdZ9LFbmuOoakIticXOEnBn9npNnINqBw9Huibf3ic24em671LIPPVOgKQOELU01nStzRwrKYB49A/640?wx_fmt=png&from=appmsg "")  
  
近日，Koi Security 安全研究员披露，在 Eclipse 基金会维护的 Open VSX Registry（open-vsx.org）中发现一个严重漏洞，攻击者一旦成功利用该漏洞，可完全接管整个 VS Code 插件市场，对全球数百万开发者构成严重威胁。  
  
  
该漏洞源于 Open VSX 项目的持续集成（CI）流程配置不当。在 GitHub Actions 的自动发布流程中，攻击者可通过构造恶意扩展或依赖，在执行 
```
npm install
```

  
 时运行任意构建脚本，并窃取拥有发布权限的令牌 
```
OVSX_PAT
```

  
。该令牌属于 
```
@open-vsx
```

  
 服务账号，具备覆盖所有插件的权限。  
  
  
简单来说，一旦令牌泄露，攻击者就可篡改任意插件，或发布包含后门的新版本插件，而这些插件又可能在用户毫无察觉的情况下通过后台自动更新部署到开发环境中。  
  
  
这意味着，任何一个插件更新都可能成为一次隐蔽的攻击。  
  
  
受影响的平台包括 Cursor、Windsurf、Google Cloud Shell Editor 和 Gitpod 等多款集成 Open VSX 的代码编辑器。Koi Security 指出，“一旦 Open VSX 被攻破，后果堪比 PyPI 或 npm 被全权接管，是供应链攻击的梦魇场景。”  
  
  
此漏洞已于 2025 年 5 月 4 日通过负责任披露报告给项目维护者，并于 6 月 25 日完成最终修复。  
  
  
MITRE ATT&CK 框架也已将“IDE 扩展”列为新的攻击技术类别，指出其可被用于持久化控制系统。研究员强调，VS Code 插件与 npm、PyPI 等包一样，属于高权限、不可见的依赖，必须被同等对待。  
  
  
“每一个插件，都是潜在的后门。”Koi Security 在报告中写道。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】#同花顺崩了# #抖音崩了# #淘宝崩了#](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070375&idx=1&sn=bb451215e72b8cc144f92d93d7b181d7&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Realtek 蓝牙协议漏洞允许攻击者通过配对过程发起拒绝服务攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070375&idx=2&sn=43a610075b530001df1d12c917a221e3&scene=21#wechat_redirect)  
  
  
  
[【安全圈】法国警方抓获BreachForum五大黑客 重创全球盗数据黑市](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070375&idx=3&sn=8a03d7051ef444718969030e62d030a1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】非洲金融机构频遭黑客攻击，开源工具助力复杂攻击链](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070375&idx=4&sn=974c75a2de2dc4972f320d62bf576a4f&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
