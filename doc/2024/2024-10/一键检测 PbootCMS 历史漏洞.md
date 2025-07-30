#  一键检测 PbootCMS 历史漏洞   
原创 xazlsec  信安之路   2024-10-28 14:06  
  
PbootCMS 是全新内核且永久开源免费的PHP企业网站开发建设管理系统，是一套高效、简洁、 强悍的可免费商用的 PHP CMS 源码，能够满足各类企业网站开发建设的需要。  
  
目前 GiiHub 更新至 3.2.10 版，官网下载版为 3.2.5，官方地址：  
> https://www.pbootcms.com/  
  
  
信安之路 POC 管理平台收录了其 7 个历史漏洞，xazlscan 已经可以一键检测，工具地址：  
> https://github.com/myh0st/xazlscan/  
  
  
测试如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEzlNQESdjbnnhQJyibibd0CIdnvUdKBnHglpIaNaR3UkQZUKghnwzfdRRw/640?wx_fmt=png&from=appmsg "")  
  
由于使用该系统的资产很多，可以参考管理后台的标题来判断系统版本，如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEzSroVyZWXeGbZ35uOH2sWgc31boibBtD0SMw7aaRApC7GShNpeH2GWww/640?wx_fmt=png&from=appmsg "")  
  
根据版本从早到晚进行梳理其目前还存在未修复完成的漏洞列表如下：  
### 一、版本小于 1.2.1  
  
存在两个 SQL 注入漏洞：  
  
1、搜索模块存在SQL注入漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEzBmUhD4MTsPX6rGibf8GHKRxLYeZO08iarZKCcZGscZibZnTd0rkaLNvjQ/640?wx_fmt=png&from=appmsg "")  
  
2、ext_price 参数存在 SQL 注入漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEz0fYWCl3VjdvEhytiakrsDvicyvYeFoUG4HupC0UcmZuicBiaXhEGrAJicgQ/640?wx_fmt=png&from=appmsg "")  
### 二、3.0.4 版本  
  
该系统 ParserController.php 文件存在命令执行漏洞，攻击者可利用该漏洞执行任意 PHP 代码，获得服务器权限，漏洞编号 CNVD-2021-32163，复现如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEz50LickoOmxCAbXZBNE1qLA1AOFSwibs3DAf2W8uj3fSVoSosCWkXhvvQ/640?wx_fmt=png&from=appmsg "")  
### 三、3.1.2 版本  
  
该版本下存在模板注入漏洞，可以通过该漏洞实现远程代码执行，如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEzg9sEpibrOvibqXHVDmuPicygk9HXauiaXJoVibd8FfDiaGfjl6gmTcnQyTng/640?wx_fmt=png&from=appmsg "")  
### 四、版本小于等于 3.1.6  
  
该版本 ParserController 前台任意代码执行漏洞，漏洞复现如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEz3LjauA1yNwGAhFjxCG4rrTXNarAKibkC39Ronu4txvttdBr0XVwxkicg/640?wx_fmt=png&from=appmsg "")  
### 五、通用性问题  
  
1、默认数据库文件可以下载，但是新版本系统会提示管理员，可一键修改数据库文件名为随机字符串，下载的数据文件为 sqlite 格式，我写了个脚本可一键下载并读取管理员用户信息：  
> https://github.com/myh0st/scripts/blob/master/pbootcms-database-download.py  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEzUNbhnPDqplrWlfgic727gDDBekPwQicibynQPSkrbyuia8A5E40aXO94Iw/640?wx_fmt=png&from=appmsg "")  
  
2、恰巧碰上账号密码可以登录系统后台的时候，可以尝试通过修改统计代码来获取 webshell，详细操作，参考：  
> https://wiki.xazlsec.com/project-45/doc-4008/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfebgXh9qQ7MgDBiaia6yWRTEzvibASMJJwE91t86JrNNuSI2X4IQjp4J3ZTgfMhqfJ3mp95Z5b0J9EvA/640?wx_fmt=png&from=appmsg "")  
### 六、安全建议  
  
1、升级系统到最新版  
  
2、修改默认口令 123456 为强口令，最好同时包含大小写字母、数字、特殊字符等  
  
3、采用非 sqlite 数据库，或者修改 sqlite 数据库名伪随机字符串  
### 七、信安之路  
  
以上所有漏洞 POC 均已被 POC 系统收录，且对应的文库已经更新完整复现报告和漏洞利用方式，均以实战的形式整理内容，旨在帮助大家在实战中提高效率，以小白都能看懂的方式，展现测试步骤。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfc1ibbG6mEdqV5Xpw0yu9UxtIoLlhiazxU4NakInEiam1mOnHHYw4pVq3nrrCc8tpnn5ictdhmNLUaHuA/640?wx_fmt=png&from=appmsg "")  
  
