#  【0day】全^程^云*OA之未授权访问+SQL注入   
网络安全007  WIN哥学安全   2024-01-06 21:35  
  
    师傅们，我又来送漏洞福利了，最近在复现某云的一些漏洞，经过不断的挖掘，终于找到了漏洞所在之处......![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Social.png "")  
  
  
    **老样子，师傅们如果有用到该平台的漏洞，要记得及时找厂商进行修复以及做好防护策略，这样子就可以预防一下啦。**  
  
**一、资产**  
```
zoomeye查询语法："images/yipeoplehover.png"或者app:"全程云OA"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpI6laZZia128md1zzP8YMRMhQeI6WqKhedY9AMgXhfvsAqK9j58HtPCuQpZfSHdawZt3pLUUiaT7Gw/640?wx_fmt=png&from=appmsg "")  
  
    zoomeye查询对于很多大型产品资产来说比较方便，有一个ZoomEye 组件搜索导航，可以快速、准确找到目标资产，感兴趣的师傅可以试试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpI6laZZia128md1zzP8YMRMiaRxqucMiaXHISVPZn59qSX1vFdBfuspHnzBKfZW4TMgib9bh52syibOVg/640?wx_fmt=png&from=appmsg "")  
  
**二、漏洞复现**  
  
**1./oa/pm/svc.asmx?op=GetUsersInfo接口**  
  
    该SVC接口直接**未授权访问**，访问之后可以发现获取用户信息接口中**userIdList参数**存在SQL注入，经过验证SOAP1.1和SOAP1.2两个请求示例数据包均存在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpI6laZZia128md1zzP8YMRMcO2TsF7ib7JDNe8Sk3yLwbRPcLtNZloz8riaZAMY08uMGRRMZ379Zeow/640?wx_fmt=png&from=appmsg "")  
  
SOAP1.1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpI6laZZia128md1zzP8YMRM8puQpvbZicvdYxvo73Xu5aGqzbeoFITnDsw7VXO2olszAeHmDhcvXVA/640?wx_fmt=png&from=appmsg "")  
  
SOAP1.2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpI6laZZia128md1zzP8YMRMedZCPgRRS6iaDCyBnvmTEiaFicDU4V2TZXiaaYN6xcwtBB7vkJWb92tD6g/640?wx_fmt=png&from=appmsg "")  
  
**2./OA/common/mod/ajax.ashx接口**  
  
    该ajax接口中使用POST传参时存在dll、class、method和id四个参数，其中**id参数**存在SQL注入，可以通过显错获取数据库信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpI6laZZia128md1zzP8YMRMhwCLqZAajSDyDftEsCNv4WfZq0iaVCa2iaHK1xbLpPjZ6hEYVialc2l2g/640?wx_fmt=png&from=appmsg "")  
  
  
### Tips:  
  
**POC地址：**点击公众号卡片回复“**240106**”  
  
****  
