#  超 4300 万 Python 安装有代码执行漏洞隐患   
山卡拉  嘶吼专业版   2025-03-11 14:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28C6zfpUZUKn9I2zAPlzHsHM34zmbvOib4IcBOXedgo4XGBLMyhe3xwHqXPxckSYZj8PARyExywUiaw/640?wx_fmt=png&from=appmsg "")  
  
在 Python JSON Logger 包（python-json-logger）中，发现了一个严重影响版本 3.2.0 和 3.2.1 的重大漏洞，编号为 CVE-2025-27607。该漏洞因对缺失依赖项 “msgspec-python313-pre” 的滥用，导致了远程代码执行（RCE）风险。最近的一项实验揭示了恶意行为者能够通过声明和操纵这一缺失的依赖项来利用该漏洞，使得这一问题引发了广泛关注。  
# 漏洞详细信息  
  
问题源于 PyPi 中 “msgspec-python313-pre” 依赖项被删除。这一删除操作使得该依赖项名称可供任何人随意声明，这就为恶意行为者创造了可乘之机，他们有可能发布同名的恶意软件包。一旦恶意行为者声明拥有该依赖项，在 Python 3.13 环境下使用 “pip install python-json-logger [dev]” 命令安装 python-json-logger 开发依赖项的用户，就可能在毫不知情的情况下，下载并执行恶意代码。  
  
该漏洞是由 @omnigodz 在研究供应链攻击时发现的。研究人员注意到，尽管 PyPi 中已不存在 “msgspec-python313-pre” 依赖项，但在 python-json-logger 版本 3.2.1 的 pyproject.toml 文件中，它仍被声明存在。  
# 受影响的版本  
  
受此次漏洞影响的版本为 3.2.0 和 3.2.1。为了在不造成实际危害的前提下演示该漏洞，研究人员临时发布了同名的非恶意软件包，之后又将其删除。这一操作使得该软件包名称与受信任的实体关联起来，有效防止了潜在恶意行为者利用此漏洞。  
# 影响与响应  
  
根据官方 PyPi BigQuery 数据库数据，python-json-logger 包应用广泛，每月下载量超 4600 万次。尽管目前没有证据表明该漏洞在公开披露前已被利用，但其潜在影响不容小觑。一旦恶意行为者声明拥有 “msgspec-python313-pre” 依赖项，所有安装 python-json-logger 开发依赖项的用户都将面临风险。  
  
为解决这一问题，python-json-logger 的维护人员迅速发布了 3.3.0 版本，该版本已移除了易受攻击的依赖项。建议使用受影响版本的用户尽快更新到最新版，以降低遭受 RCE 攻击的风险。  
  
此次事件凸显了维护和确保软件包依赖关系安全的重要性，同时也强调了在开源生态系统中，对供应链安全保持高度警惕的必要性。虽然这一特定漏洞已得到解决，但它提醒着开发人员和用户，要时刻关注潜在安全风险，并及时将软件更新到最新版本。  
  
参考及来源：https://gbhackers.com/over-43-million-python-installations-vulnerable/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28C6zfpUZUKn9I2zAPlzHsHiad8mwQ2q8ez3eKzlJM18J4MLroRrT0kibtrOuvtB77y5vUzygJCibdeQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28C6zfpUZUKn9I2zAPlzHsHU51zb5Spa6pFY8gR2zvFArwOI13qgoummAcJqRQnFib2ESbXJ8vakww/640?wx_fmt=png&from=appmsg "")  
  
  
