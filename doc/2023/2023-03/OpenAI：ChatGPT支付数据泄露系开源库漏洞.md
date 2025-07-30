#  OpenAI：ChatGPT支付数据泄露系开源库漏洞   
 关键基础设施安全应急响应中心   2023-03-28 15:08  
  
Redis开源库漏洞引发ChatGPT支付数据泄露。  
# 事件回顾  
  
3月20日，多名ChatGPT订阅用户称在其订阅页面看到了其他用户的邮箱地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iceFWxia8HW0evmJSuVfsWSFl789lMWD8veQxnS6kW1YzibJPL53Uar84LVyaTksTtLOaNSBsdVIxlg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iceFWxia8HW0evmJSuVfsWSF3ynoJkyfNHU3OurJXXawp723o4lpuY9Ms1ofojUqcNHZsdtch0m9Rg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 推特原文  
  
随后，OpenAI将ChatGPT下线并调查了这一问题，但并未说明ChatGPT停止服务的原因。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iceFWxia8HW0evmJSuVfsWSFVX50OyhIabPytrPg0R1nwibELAS6YmPT9kBibYKC3q2T4AC5hCSwTqYA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图 ChatGPT停止服务期间的状态信息  
# 数据泄露后的开源库漏洞  
  
3月24日，OpenAI发布报告称发生这一意外事件的原因是Redis客户端开源库redis-py中存在漏洞，引发ChatGPT暴露了其他用户的聊天会话查询和个人信息，大约有1.2%的ChatGPT Plus订阅用户受到影响。暴露的信息包括订阅用户姓名、邮件地址、支付地址、信用卡后四位数字和信用卡过期日期。  
  
OpenAI称，该问题发生的时间窗口为9小时。在ChatGPT停止服务之前的9个小时，部分用户可能可以看到其他用户的姓名、邮箱地址、支付地址等信息，但信用卡号并未完全暴露。OpenAI认为数据泄露的影响用户非常少，因为需要进行特定步骤才可以看到这些信息，包括：  
  
打开在3月20日1点-10点之间发送的订阅确认邮件；  
  
在ChatGPT中，点击我的账户—>管理我的订阅。  
  
OpenAI发现该安全问题后，已与Redis维护人员取得联系，并发布了补丁来修复该安全漏洞。OpenAI称已联系了所有个人支付信息暴露的ChatGPT用户。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/openai-chatgpt-payment-data-leak-caused-by-open-source-bug/  
  
  
  
原文来源：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
