#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re

# 模拟第一个响应的解析
response1 = '''
{
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": "分析结果：{\\"res\\":\\"true\\", \\"reason\\":\\"响应结构一致，判定越权成功\\"}"
                    }
                ]
            }
        }
    ]
}
'''

# 定义解析模式 - 修复：使用非贪婪匹配并正确处理嵌套引号
GEMINI_TEXT_PATTERN = re.compile(r'"text":\s*"((?:[^"\\]|\\.)*)"\s*}', re.DOTALL)
RES_FIELD_PATTERN = re.compile(r'[\'\"]res[\'\"]:\s*[\'\"](\w+)[\'\"]', re.IGNORECASE)

print("=== 调试 Gemini 响应解析 ===")
print("原始响应：", response1.strip())

# 提取 text 字段
gemini_text_match = GEMINI_TEXT_PATTERN.search(response1)
if gemini_text_match:
    text_content = gemini_text_match.group(1)
    print("\n提取的 text 内容（原始）:", repr(text_content))
    
    # 解码转义字符
    text_content = text_content.replace('\\n', '\n').replace('\\\"', '\"').replace('\\\\', '\\')
    print("解码后的 text 内容：", repr(text_content))
    
    # 直接搜索 res 字段
    res_in_text = RES_FIELD_PATTERN.search(text_content)
    if res_in_text:
        print("找到 res 字段：", res_in_text.group(1))
    else:
        print("未找到 res 字段，尝试 JSON 解析...")
        
        # 尝试 JSON 解析
        if '{' in text_content and '}' in text_content:
            json_start = text_content.find('{')
            json_end = text_content.rfind('}') + 1
            json_str = text_content[json_start:json_end]
            print("提取的 JSON 字符串：", repr(json_str))
            
            try:
                parsed = json.loads(json_str)
                print("解析的 JSON:", parsed)
                if 'res' in parsed:
                    print("✅ 找到 res 值：", parsed['res'])
                else:
                    print("❌ JSON 中没有 res 字段")
            except Exception as e:
                print("❌ JSON 解析失败：", str(e))
else:
    print("❌ 未找到 text 字段")

# 测试改进的正则表达式
print("\n=== 测试改进的正则表达式 ===")
# 尝试更直接的模式
DIRECT_RES_PATTERN = re.compile(r'res.*?[\'"](\w+)[\'"]', re.IGNORECASE)
match = DIRECT_RES_PATTERN.search(response1)
if match:
    print("✅ 直接模式找到：", match.group(1))
else:
    print("❌ 直接模式未找到")

# 尝试更宽松的模式
LOOSE_RES_PATTERN = re.compile(r'res[\'"]?\s*:\s*[\'"](\w+)[\'"]', re.IGNORECASE)
match = LOOSE_RES_PATTERN.search(response1)
if match:
    print("✅ 宽松模式找到：", match.group(1))
else:
    print("❌ 宽松模式未找到")
