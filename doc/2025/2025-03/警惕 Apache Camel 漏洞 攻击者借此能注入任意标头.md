#  警惕 Apache Camel 漏洞 攻击者借此能注入任意标头   
山卡拉  嘶吼专业版   2025-03-12 14:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28d7LAIiarYHMmOZNuglAV81AJ8cb0zPhHjsyoWKzJcnLfic8hPTcCTibFaIibtteJ1lfjnTzUP0QAia9Q/640?wx_fmt=png&from=appmsg "")  
  
Apache Camel 中近期披露的一个安全漏洞（编号为 CVE - 2025 - 27636），已引发整个网络安全社区的高度警惕。该漏洞允许攻击者向 Camel Exec 组件配置注入任意标头，进而有可能实现远程代码执行（RCE）。  
  
受此漏洞影响的版本众多，涵盖 3.10.0 至 3.22.3、4.8.0 至 4.8.4 以及 4.10.0 至 4.10.1 等多个版本。此次漏洞充分凸显了 Apache Camel 中配置错误的标头过滤所带来的巨大危险。Apache Camel 作为一款广泛应用的集成框架，其主要作用是连接各类系统和应用程序。  
  
安全专家强烈敦促正在使用易受攻击版本的组织，立即对其系统进行修补，以此降低风险。根据 Github 的报告，该漏洞的根源在于 Camel 框架对标头的处理出现错误，尤其是在标头命名大小写发生变化的情况下。利用这一漏洞，攻击者能够绕过过滤器，覆盖 Camel 配置中指定的静态命令。  
# 概念验证（PoC）  
  
一个存在漏洞的示例应用程序，能够演示如何利用 Camel Exec 组件实现远程代码执行。以下是存在漏洞的代码示例：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28d7LAIiarYHMmOZNuglAV811oq9GeljKaIKfMwSoLkd6ffKB1Kd54wwUhd5Z8Jdde77pia2NF5oOmA/640?wx_fmt=png&from=appmsg "")  
  
在此场景中，应用程序对外公开了一个执行 “whoami” 命令的 HTTP 端点。虽然该命令在代码中是静态定义的，但攻击者可以通过特制的标头对其进行覆盖。  
# 漏洞利用细节  
  
该漏洞的工作原理是向易受攻击的端点发送恶意标头。例如：  
  
$ curl “http://localhost:80/vulnerable” –header “CAmelExecCommandExecutable: ls”  
  
此命令会覆盖默认的执行行为并显示目录内容。同样，攻击者可以使用标头 CamelExecCommandArgs 传递参数：  
  
$ curl “http://localhost:80/vulnerable” –header “CAmelExecCommandExecutable：ping” –header “CAmelExecCommandArgs：-c 2 8.8.8.8”  
  
该漏洞源于对标头命名约定的不当处理。Camel 原本旨在过滤掉诸如 CamelExecCommandExecutable 之类的标头，但大小写变体 CAmelExecCommandExecutable 却绕过了保护机制，从而允许任意命令执行。当使用常规标头，而不利用区分大小写的缺陷时，应用程序将按预期运行，执行静态命令：  
  
$ curl “http://localhost:80/vulnerable” –header “CamelExecCommandExecutable: ls”  
# 影响与缓解  
  
该漏洞所产生的后果极其严重，因为攻击者能够在易受攻击的系统上执行任意命令，这可能导致敏感数据泄露、实现横向移动，甚至造成服务中断。Apache 已发布公告，承认了该漏洞的存在，并正在积极努力为受影响的版本发布补丁。为了防御 CVE - 2025 - 27636，建议用户采取以下措施：  
  
· 升级 Apache Camel：在 Apache 发布修补版本后，及时应用更新。  
  
· 限制端点访问：将易受攻击的端点暴露范围限制在受信任的网络内。  
  
· 监控危害指标（IoC）：在日志中留意异常的 HTTP 标头或命令执行情况。  
  
随着攻击者越来越多地将目标对准 Apache Camel 等集成框架，各组织必须高度重视安全更新，并强化访问控制，以最大程度降低风险。此漏洞清晰地警示我们，即便是细微的缺陷，也可能给现代 IT 基础设施带来毁灭性的后果。  
  
参考及来源：https://gbhackers.com/apache-camel-vulnerability/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28d7LAIiarYHMmOZNuglAV81UXyXHU4xAyAAb1OfsmlaOFxkL8Avia5odT6z07UbYGczNsn3Ca9XyQA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28d7LAIiarYHMmOZNuglAV81NaiaaqAXN5Wc1pV92cibFp5kVtibLibO6UqyzGmGVpUd67d8Zmj7yGR8Rw/640?wx_fmt=png&from=appmsg "")  
  
  
