> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU3MjU4MjM3MQ==&mid=2247490132&idx=1&sn=07ba6c193632c29209e311fae62797fa

#  【代码审计】某产品UserCreateService存在任意用户添加漏洞分析  
原创 xiachuchunmo  银遁安全团队   2025-06-30 00:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
代码分析  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
该系统采用shiro进行权限控制，其中/api/接口无需鉴权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibZRwbAHx6l1gVo1ZxzLx3z3zUbviaPFjFoeDwq0lDzNWiad9UTtib7mp9pe47BldibUt85NIgPeiaxtag/640?wx_fmt=png&from=appmsg "")  
  
发现存在  

```
addUserCreateService
```

  
方法可添加用户，路由为  

```
/api/personSeal/UserCreateService
```

  
，请求参数为  

```
json
```

  
格式，并且该接口无需鉴权。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibZRwbAHx6l1gVo1ZxzLx3zZnyCRtcEegKDMGXplDic5VgOgwwiamDL47ZCEiax7KAVPFEpkP2nichG7A/640?wx_fmt=png&from=appmsg "")  
  
  
代码这里判断  
传入的  

```
json
```

  
字段中  
是否包含  

```
bimRequestId
```

  
、  

```
bimRemotePwd
```

  
、  

```
bimRemoteUser
```

  
、  

```
loginName
```

  
、  

```
fullName
```

  
、  

```
orgId
```

  
字段  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibZRwbAHx6l1gVo1ZxzLx3zbtkdUM03NPvW6N58OPInoZmUJmr7z6icFm38AuKzArHiaul0Hhhew0sw/640?wx_fmt=png&from=appmsg "")  
  
调用工具类  

```
apiPersonUtil
```

  
的  

```
checkUnamePass
```

  
方法，跟入  

```
checkUnamePass
```

  
方法中，其中  

```
bimRemoteUser
```

  
需为  

```
ZGJ
```

  
，  

```
bimRemotePwd
```

  
为  

```
123456
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibZRwbAHx6l1gVo1ZxzLx3z0m59zDvRd8dxmhoztaHa8lSqAYZOal4MI7uiamnHZricTfibzP8s7ia8NQ/640?wx_fmt=png&from=appmsg "")  
  
这里根据传入的  

```
orgId
```

  
进行查询，需使  

```
departmentList
```

  
不为空  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibZRwbAHx6l1gVo1ZxzLx3zNRXDjia6xpzfMGvkJMfjYm4kxhqQjnRLmorXDDOslcAvg4qAiboHP06Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibZRwbAHx6l1gVo1ZxzLx3zpe6T7Pj6mzu8U6YqKoMUJ1sdoGca0L4ZW2FWjCpWR15LNPG14xuGgA/640?wx_fmt=png&from=appmsg "")  
  
接下来就是正常的添加用户操作，其中默认密码设置为  

```
666666
```

  
  

```

```

  

```


```

  

```

```

  
其中  

```
orgId
```

  
可通过  

```
/api/personSeal/QueryAllOrgIdsService
```

  
获取  
  

```

```

  
使用账号  

```
xxxxxxxxxxx/666666
```

  
成功登录系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yeJvia5dNx5ibZRwbAHx6l1gVo1ZxzLx3zbu0z6ibqaSaqvMaBMAn1UyfYLGc7uEy98JLgScibhdc7xzKfBODsNLew/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
  
