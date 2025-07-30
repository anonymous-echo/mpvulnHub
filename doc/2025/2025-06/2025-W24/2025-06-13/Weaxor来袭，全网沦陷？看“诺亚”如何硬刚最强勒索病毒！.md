> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NDgxMzgxNA==&mid=2247496910&idx=1&sn=b19571e708de957bed03fe85fd5cba48

#  Weaxor来袭，全网沦陷？看“诺亚”如何硬刚最强勒索病毒！  
 第59号   2025-06-13 09:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQGyphzA3WXmWFrC0a5pL4xhldY0snibzH1jjNxywZYib5qa0VtICh94iag/640?wx_fmt=gif&from=appmsg "")  
  
近期，美创第59号安全实验室监测到多起高度相似的勒索病毒事件，该勒索病毒通过RDP爆破、攻击数据库服务、应用程序1DAY漏洞等方式感染受害主机。一旦得手，病毒会在主机上加密文件进行勒索，加密文件后缀包括但不限于.rox、.wxr、.wxx、.weaxor等。  
  
  
经分析，该勒索病毒为Weaxor家族  
。Weaxor家族为热门勒索病毒家族--Mallox家族的新变种。Mallox勒索病毒自2021年出现，至今已实施多起臭名昭著的勒索事件。Weaxor家族作为Mallox家族的变种，自2024年底出现后迅速取代Mallox的主流地位，在多方权威分析统计报告中，Weaxor家族一直是2025年勒索病毒占比排行榜的月度“常胜冠军”。  
  
  
  
  
  
  
**01**  
  
  
  
**Weaxor勒索病毒感染表现**  
  
  
  
  
  
  
  
  
  
  
  
  
受害主机在感染Weaxor勒索病毒后，文件会被加密成**.rox、.wxr、.wxx、.weaxor**  
等格式。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQRuibicicaa4RVHZWxbEtdmx9fCLib4VWRaiasVmCWpvAabyx5pydcZS9nJA/640?wx_fmt=png&from=appmsg "")  
  
  
同时，病毒会释放勒索信文件RECOVERY INFO.txt，勒索信内容如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQW9EbmYVhoYSS5ZegduntWykAk0iaCic5GfuicAF3rrR27sf9uYfN7tJfQ/640?wx_fmt=png&from=appmsg "")  
  
  
此外在加密器文件目录下，还会生成一个wxr.txt文件，其中记录了被勒索用户的标志信息以及受害主机信息等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQZtQ3mic3zkjRaKaCffRUVDOWu0e9j7OVNrexMVpmpbDmgl7RpNVDO2w/640?wx_fmt=png&from=appmsg "")  
  
  
**02**  
  
**Weaxor勒索病毒样本分析**  
  
  
  
  
  
  
  
  
  
  
  
  
此次用于分析的Weaxor勒索病毒样本为2025年2月份编译的版本，其使用C++语言进行开发和编译。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQicJKJXOnibYg5IjAtNYJgyLqvXt2U2eweIM8smHKI8ibHaF4enicEsiaZ0A/640?wx_fmt=png&from=appmsg "")  
  
  
**使用静态分析工具对样本文件进行分析，发现其行为如下：**  
  
**1. 环境检查：**  
病毒运行后，首先**检查系统的语言**  
，在特定语言环境下会直接退出程序，不进行加密勒索操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQLG1CTdHib9YP5PNicOib5RRPZkxOW25ozDLBiazhH6yicFjvfTS0JhqXtxQ/640?wx_fmt=png&from=appmsg "")  
  
  
**2. 信息收集：**  
病毒会获取操作系统、网卡、磁盘等信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQLcvlu0HBgmlDGuibzdibrfYMOZ5rJY4PQcrU3GvDIULr9kiatzvEZEeAQ/640?wx_fmt=png&from=appmsg "")  
  
  
**3. 信息外传：**  
上述信息收集完成后会写入到txt文件中，并发送至以下地址  
：  
http://193.143.1.139/Ujdu8jjooue/biweax.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQibSb2fGd357BDkVdicciaOBAa0R02ict7tptpNkRMbLz9stElibb7KT4icHQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**4. 破坏性操作：**  
  
·**删除注册表项**  
：  
猜测可能是为了防止受害主机上这些程序被安全监控软件或者运维人员使用，造成勒索病毒无法正常进行或者勒索进程中断，确保攻击影响最大化。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQnnEnSPx72R9Gqt3WOaibDEaPuRicmEYHLdKtcd3NJzbGOr8kkayygtBA/640?wx_fmt=png&from=appmsg "")  
  
  
·**删除卷影副本**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQBzaIe2CZmdMCoTpakOqqp10jlFBX7cwK6lElSiad7DZxFt6lNibgqtRw/640?wx_fmt=png&from=appmsg "")  
  
  
·**设置白名单**  
：设置不进行加密的白名单文件以及文件目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQMF8j0EfBx2NZybyD6icF9GMZhw3lSIgo57lTBrNhA3Yfsj2N1tNWeZA/640?wx_fmt=png&from=appmsg "")  
  
  
**5. 文件加密**  
：完成上述前置工作后，Weaxor勒索病毒样本就会开始遍历并挂载所有磁盘卷，读取文件进行**加密操作**  
，并将除白名单外的所有文件命名为.wxr后缀。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQqUnfJbGUYQICUbrplHpHALd5vO44LOb9ibwpEXHDHFSrB9RHz7zbOWw/640?wx_fmt=png&from=appmsg "")  
  
  
**一朝诺亚 终生免疫**  
  
  
**美创诺亚防勒索**  
  
  
  
为有效应对已知或未知勒索病毒的威胁，美创通过对大量勒索病毒的深度分析，基于零信任原则，创造性地研发出针对勒索病毒的终端防护产品——**诺亚防勒索系统**  
。诺亚防勒索在不关心漏洞传播方式的情况下，  
**可防护任何已知或未知的勒索病毒**  
。  
以下为诺亚防勒索针对勒索病毒的实际防护效果演示：  
  
  
诺亚防勒索可通过服务端统一下发策略并更新。默认策略可保护office文档（如需保护数据库文件可通过添加策略一键保护）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQpIFx7ViaU2aibRgb4rw9oPGo33Qp4tibU3r5krKz63lmzgNauAKBnAJYQ/640?wx_fmt=png&from=appmsg "")  
  
**未开启「诺亚防勒索」防护**  
  
在test目录下，添加以下文件，当服务器感染勒索病毒，该文件被加密，增加统一的异常后缀（如.wxr），且**无法正常打开**  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQfXJq0pFEPCsT5jnrRMhCm1PEyib1yqiaPZSlXgC2vSueibzVicZXoQI6pg/640?wx_fmt=png&from=appmsg "")  
  
**开启「诺亚防勒索」防护**  
  
双击执行病毒文件，当勒索病毒尝试加密被保护文件，即test目录下的文件时，  
**诺亚防勒索会立即弹出警告并拦截该行为**  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQ8VBMTrh4GBFuXDFJ3kdUvRK0W29AbeIMF4y0ncEROaQmkdk7wTeWQA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQoU9MAY8tvwXquvDqZ7UGxrY39Zd6Phjv14Qw69l48icXFWEBmQKII8Q/640?wx_fmt=png&from=appmsg "")  
  
  
检查系统，可见
```
test
```

  
目录下的被测试文件**未被加密**  
，**可被正常打开**  
，诺亚防勒索成功阻断了恶意软件的加密行为。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQTIznkbhhSjibMx2Nvbiab3vQOsnleNYmibLgicgrXlVpeQMicLaUNnrMgYA/640?wx_fmt=png&from=appmsg "")  
  
**开启「诺亚防勒索-堡垒模式」**  
  
为全方位守护系统文件安全，诺亚防勒索提供「堡垒模式」。堡垒模式尤其适用于ATM机等极少更新的亚终端设备。一键开启堡垒模式后，所有进入终端的可执行文件都将被阻止运行，有效阻断任何新的应用程序运行，包括**勒索软件、已知勒索病毒、未知勒索病毒、挖矿病毒**  
，达到诺亚防勒索的最强防护模式。  
  
  
在堡垒模式下，尝试执行该病毒文件，立刻被移除到隔离区，病毒运行被阻断。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQOHPNnWJcqicnYcJa5icVq0GCUR0uxPb2dnHQEmg3bhYqZfXOdsOgfCkg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gauNkjeXJb54H2xHRPBQmLaaNIGr6syQtGnY3LoM8bPYqwCjrgCtBJFxv6CySMibibaBoJK6hiaHM4cQRdom4Z2cg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
“一朝诺亚，终生免疫”，今天，诺亚防勒索已赢得各级政府单位、医院、教育、能源和大型制造企业等众多用户的认可，成为勒索病毒洪水式侵袭环境下的首要选择。  
  
  
### 美创科技第59号安全实验室，建有余杭区首家“网络与信息安全管理员技能大师工作室”，专注于数据安全技术领域研究，聚焦于安全防御理念、攻防技术、漏洞挖掘等专业研究，进行知识产权转化并赋能于产品。自2021年起，累计向 CNVD、CNNVD 等平台提报数千个高质量原创漏洞，并入选国家信息安全漏洞库（CNNVD）技术支撑单位（二级）、信创政务产品安全漏洞库支撑单位，团队申请发明专利二十余项，发表多篇科技论文，著有《Java代码审计实战》《数据安全实践指南》、《内网渗透实战攻略》等。  
  
  
  
  
  
  
[#勒索防护]()  
  [#勒索病毒]()  
   
  
