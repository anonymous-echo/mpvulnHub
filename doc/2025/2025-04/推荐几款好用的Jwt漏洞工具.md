#  推荐几款好用的Jwt漏洞工具   
原创 夜风Sec  夜风Sec   2025-04-14 09:55  
  
## 集成的Jwt工具 - venom_jwt  
  
Github项目地址：https://github.com/z-bool/Venom-JWT  
  
![jwttool02](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn33MGlJqvMq7tBbpibLXQuP3ic9ZaiayvZoABYeiaBGaGichh0j2cuSfib4YZg/640?wx_fmt=png&from=appmsg "")  
  
jwttool02  
## 爆破Jwt - c-jwt-cracker  
  
Github项目地址：https://github.com/brendan-rius/c-jwt-cracker  
```
./jwt-crack <jwt_data>

```  
## Jwt分析工具  
  
Github项目地址：https://github.com/ticarpi/jwt_tool  
```
python3 jwt_tool.py <Jwt_data>

```  
## Bp扩展 - JSON Web Tokens & JWT Editor  
  
Github项目地址：https://github.com/dwyl/learn-json-web-tokens  
  
Github项目地址：https://github.com/blackberry/jwt-editor  
  
![jwttool01](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3K6H1hykyrYLia811HWmkadtiaIaXibrKQicqkDwFsUVjpW47GTP57gOo8A/640?wx_fmt=png&from=appmsg "")  
  
jwttool01  
## hashcat爆破密钥  
```
hashcat -a 0 -m 16500 <jwt_data> <dict>

```  
  
![jwttool00](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3ozlGl0Mfv4GVkN5qpMqwCq2B5EONaGAiaWEsia3sRVS4mWr7lwUTMia9A/640?wx_fmt=png&from=appmsg "")  
  
jwttool00  
## jwt密钥爆破字典  
  
https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list  
  
  
