import os
import os
import shutil
from datetime import datetime

# 定义目录路径
md_dir = os.path.join(os.getcwd(), 'md')
daily_dir = os.path.join(os.getcwd(), 'daily')
daily_file = os.path.join(daily_dir, 'daily.md')

# 确保daily目录存在
os.makedirs(daily_dir, exist_ok=True)

# 获取md目录下所有yyyy-mm-dd.md格式的文件
md_files = []
for file in os.listdir(md_dir):
    if len(file) == 13 and file.endswith('.md'):
        try:
            # 尝试解析日期格式
            date_str = file[:10]
            datetime.strptime(date_str, '%Y-%m-%d')
            md_files.append((date_str, file))
        except ValueError:
            continue

# 如果没有找到符合格式的文件，退出
if not md_files:
    print("没有找到符合格式的安全态势报告文件")
    exit(1)

# 按日期排序，获取最新的文件
md_files.sort(key=lambda x: x[0], reverse=True)
latest_date, latest_file = md_files[0]
latest_file_path = os.path.join(md_dir, latest_file)

# 复制最新文件到daily.md
try:
    shutil.copy2(latest_file_path, daily_file)
    print(f"成功将 {latest_file} 复制到 {daily_file}")
    
    # 读取daily.md的标题
    with open(daily_file, 'r', encoding='utf-8') as f:
        first_line = f.readline().strip()
        title = first_line.lstrip('# ')
    
    # 获取当前时间
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 定义日志文件路径
    log_file = os.path.join(daily_dir, 'update.log')
    
    # 定义日志格式参数
    time_width = 20   # 时间列宽度
    separator = '-' * 50 + '\n'

    # 定义日志目录和文件路径
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'daily')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'update.log')

    # 检查日志文件是否存在并处理
    file_exists = os.path.isfile(log_file)
    existing_entries = []

    # 如果文件存在，检查格式并读取现有条目
    if file_exists:
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            if lines:
                # 跳过表头行（如果有）
                start_idx = 0
                if any('标题' in line for line in lines[:2]):
                    # 找到包含'标题'的行作为表头
                    for i, line in enumerate(lines[:2]):
                        if '标题' in line:
                            start_idx = i + 1
                            break
                
                # 读取所有条目
                for line in lines[start_idx:]:
                    # 提取标题和时间信息
                    import re
                    
                    # 尝试匹配标准时间格式 (YYYY-MM-DD HH:MM:SS)
                    time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    
                    if time_match:
                        time_old = time_match.group(1)
                        # 提取标题（时间前面的所有内容）
                        title_old = line[:time_match.start()].strip()
                        # 清理标题中的非文字字符
                        title_old = re.sub(r'^[^\w\u4e00-\u9fa5]+', '', title_old)
                        existing_entries.append((title_old, time_old))
                    else:
                        # 尝试匹配CSV格式
                        if ',' in line:
                            parts = line.split(',', 1)
                            if len(parts) == 2:
                                title_old = parts[0].strip()
                                time_old = parts[1].strip()
                                # 尝试从时间部分提取有效格式
                                date_match = re.search(r'(\d{4}-\d{2}-\d{2})', time_old)
                                time_part_match = re.search(r'(\d{2}:\d{2}:\d{2})', time_old)
                                if date_match and time_part_match:
                                    time_old = f"{date_match.group(1)} {time_part_match.group(1)}"
                                    existing_entries.append((title_old, time_old))
                        else:
                            # 尝试匹配可能的日期和时间部分
                            date_match = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                            time_part_match = re.search(r'(\d{2}:\d{2}:\d{2})', line)
                            if date_match and time_part_match:
                                time_old = f"{date_match.group(1)} {time_part_match.group(1)}"
                                # 提取标题（去掉日期和时间）
                                title_old = line.replace(date_match.group(1), '').replace(time_part_match.group(1), '').strip()
                                title_old = re.sub(r'^[^\w\u4e00-\u9fa5]+', '', title_old)
                                existing_entries.append((title_old, time_old))
                        # else: 无法解析，跳过

    # 添加新条目
    existing_entries.append((title, current_time))

    # 清理无效条目并去重
    valid_entries = []
    seen = set()
    for t, time in existing_entries:
        if t and time and (t, time) not in seen:
            seen.add((t, time))
            # 确保时间格式正确
            import re
            if not re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', time):
                # 尝试修复时间格式
                date_match = re.search(r'(\d{4}-\d{2}-\d{2})', time)
                time_match = re.search(r'(\d{2}:\d{2}:\d{2})', time)
                if date_match and time_match:
                    time = f"{date_match.group(1)} {time_match.group(1)}"
                else:
                    continue
            valid_entries.append((t, time))

    # 动态计算标题列宽度（取最长标题长度+2）
    title_width = max(len(t) for t, _ in valid_entries) + 2
    time_width = 20  # 固定时间列宽度

    # 定义格式化字符串
    header_format = f"{{:<{title_width}}}{{:>{time_width}}}\n"
    entry_format = f"{{:<{title_width}}}{{:>{time_width}}}\n"
    separator = '-' * (title_width + time_width) + '\n'

    # 写入日志
    with open(log_file, 'w', encoding='utf-8') as f:
        # 写入表头
        f.write(header_format.format("标题", "更新时间"))
        f.write(separator)
        # 写入所有条目
        for t, time in valid_entries:
            f.write(entry_format.format(t, time))
    
    # 构造日志条目字符串用于打印
    last_entry = entry_format.format(title, current_time)
    print(f"成功写入日志: {last_entry.strip()}")

except Exception as e:
    print(f"复制文件时出错: {e}")
    exit(1)