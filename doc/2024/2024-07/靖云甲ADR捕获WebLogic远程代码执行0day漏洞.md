#  靖云甲ADR捕获WebLogic远程代码执行0day漏洞   
 实战攻防   2024-07-24 18:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/eCphtEDOn1vHgGwRpTQdtNrehRHPecX6URD4LmzLAYrfYyFzpXsztbrFShmfZZw4q0JlLhbypicle09EfehzDQA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
WebLogic 是在金融、运营商、能源、中央企业、大型企业中常用的中间件，也是安全研究的重点关注对象，其覆盖的应用系统数量极多，且多数应用皆会对外提供服务，此类大型中间件的漏洞可谓是进攻利器。  
  
  
为了应对日新月异的攻击手段以及第三方外采系统、老旧业务系统防护难等问题，很多客户选择边界无限为Web应用套上“靖云甲”，该方案基于应用运行时自防护——RASP技术，专门针对应用和Java中间件进行重点防御，给用户的应用增加最后一道防线，使其免受应用层的0day漏洞和内存马攻击。  
  
  
近期在某金融行业客户的现场，**靖云甲ADR捕获到了反序列化与命令执行相关的攻击告警**，最初我们认为是一个常见的漏洞利用告警，但是随着排查并深入分析告警信息，其攻击执行是通过Weblogic IIOP协议的反序列化漏洞进行操作的，并且从调用链来看攻击者挖掘到了新的漏洞利用入口，攻击手法可无视官方最新提供的反序列化黑名单，最终可利用该漏洞实现远程代码执行。  
  
  
目前靖云甲ADR已经协助用户捕获了相关Weblogic漏洞利用。目前近期部署的靖云甲ADR工具无需升级便可检测和防御该漏洞的利用，**用户可部署靖云甲ADR来防御该漏洞的攻击。**  
  
  
**漏洞信息**  
  
  
  
  
  
  
**漏洞类型：**  
远程代码执行  
  
**漏洞等级：**  
高危  
  
**漏洞所需权限：**  
无权限需求  
  
  
攻击者可以利用Weblogic暴露的IIOP协议进行反序列化，实现远程代码执行，获取服务器权限。下面为靖云甲ADR完整捕获流程，可以看到攻击者首先进行了反序列化操作，然后利用反序列化进行命令执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/eCphtEDOn1vHgGwRpTQdtNrehRHPecX6L5wDhyy2WgaiaDIt7pHD3lKW4rXU4aEMPShc4Qy7JQ9icGoVM7nQQwhQ/640?wx_fmt=png&from=appmsg "")  
  
图一 反序列化漏洞利用告警  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/eCphtEDOn1vHgGwRpTQdtNrehRHPecX6mAoJiaoeaUg85w2WseU4XzdFv40yHSibaD96hfnrAn56kFLg1vyUueBA/640?wx_fmt=png&from=appmsg "")  
  
图二 远程命令执行告警  
  
  
**漏洞利用条件**  
  
  
  
  
  
  
1.Weblogic对外开放IIOP协议访问；  
  
2.整个漏洞利用过程无需出网。  
  
  
**漏洞影响范围**  
  
  
  
  
  
  
版本≤ WebLogic Server 12.2.1.4.0  
  
版本≤ WebLogic Server 14.1.1.0.0  
  
  
**修复方案**  
  
  
  
  
  
  
1.临时缓解措施：禁用 T3/IIOP 协议，或针对白名单IP进行开放；  
  
**2.安装基于RASP技术的靖云甲ADR，可天然免疫该漏洞攻击。**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_svg/ibkKkoaQFco520oT7HFXURDnTaSDRudVLx77uuvBBDibbqS94pHAZL8yaPOB0KWLgnwqaF9ibVsz2JFZzqHtBpAz9M2vIY3yYgN/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/eCphtEDOn1vHgGwRpTQdtNrehRHPecX6PkJlPbZbSglIfz4zCdM5frK3mDuiar5V1o8QFICGUicAb08z9iaYeEDgg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
****  
  
