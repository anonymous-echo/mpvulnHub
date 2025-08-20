import os
import markdown
from datetime import datetime

# 配置常量
DAILY_DIR = 'daily'
DAILY_FILE = os.path.join(DAILY_DIR, 'daily.md')
HTML_FILE = os.path.join(DAILY_DIR, 'daily.html')


def convert_md_to_html():
    """
    将daily.md转换为HTML文件
    """
    try:
        # 检查daily.md是否存在
        if not os.path.exists(DAILY_FILE):
            print(f"错误: {DAILY_FILE} 不存在")
            return False

        # 读取Markdown内容
        with open(DAILY_FILE, 'r', encoding='utf-8') as f:
            md_content = f.read()

        # 转换为HTML
        html_content = markdown.markdown(md_content)

        # 添加基本HTML结构
        full_html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全威胁态势报告 - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: 'Microsoft YaHei', Arial, sans-serif; line-height: 1.6; margin: 20px; max-width: 800px; margin-left: auto; margin-right: auto; }}
        h1, h2, h3 {{ color: #333; }}
        pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        code {{ background-color: #f5f5f5; padding: 2px 5px; border-radius: 3px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        img {{ max-width: 100%; height: auto; }}
    </style>
</head>
<body>
    {html_content}
    <footer>
        <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </footer>
</body>
</html>
"""

        # 写入HTML文件
        with open(HTML_FILE, 'w', encoding='utf-8') as f:
            f.write(full_html)

        print(f"成功将 {DAILY_FILE} 转换为 {HTML_FILE}")
        return True

    except Exception as e:
        print(f"转换Markdown到HTML时出错: {e}")
        return False


if __name__ == "__main__":
    convert_md_to_html()



# 使用说明:
# 1. 安装依赖: pip install markdown
# 2. 运行脚本: python md_to_html.py
# 3. 脚本会读取daily/daily.md并生成daily/daily.html