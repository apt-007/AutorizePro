#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re

def extract_gemini_text(response_string):
    """使用JSON解析提取Gemini响应中的text内容"""
    try:
        # 直接解析JSON响应
        parsed = json.loads(response_string)
        
        # 导航到text字段
        if 'candidates' in parsed:
            for candidate in parsed['candidates']:
                if 'content' in candidate:
                    content = candidate['content']
                    if 'parts' in content:
                        for part in content['parts']:
                            if 'text' in part:
                                return part['text']
        return None
    except Exception as e:
        print("JSON解析失败:", str(e))
        return None

# 测试响应
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

response2 = '''
{
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "text": "{\\"res\\":\\"false\\", \\"reason\\":\\"权限验证失败\\"}"
                    }
                ]
            }
        }
    ]
}
'''

# 定义解析模式
RES_FIELD_PATTERN = re.compile(r'[\'\"]res[\'\"]:\s*[\'\"](\w+)[\'\"]', re.IGNORECASE)

def extract_res_value_improved(response_string):
    """改进的res值提取函数"""
    try:
        # 步骤1：使用JSON解析提取text内容
        text_content = extract_gemini_text(response_string)
        if not text_content:
            return ""
        
        print("提取的text内容:", repr(text_content))
        
        # 步骤2：解码转义字符
        text_content = text_content.replace('\\n', '\n').replace('\\\"', '\"').replace('\\\\', '\\')
        print("解码后的text内容:", repr(text_content))
        
        # 步骤3：搜索res字段
        res_match = RES_FIELD_PATTERN.search(text_content)
        if res_match:
            print("✅ 通过正则找到res:", res_match.group(1))
            return res_match.group(1).lower()
        
        # 步骤4：尝试JSON解析
        if '{' in text_content and '}' in text_content:
            json_start = text_content.find('{')
            json_end = text_content.rfind('}') + 1
            json_str = text_content[json_start:json_end]
            print("提取JSON字符串:", repr(json_str))
            
            try:
                parsed = json.loads(json_str)
                if 'res' in parsed:
                    print("✅ 通过JSON解析找到res:", parsed['res'])
                    return str(parsed['res']).lower()
            except Exception as e:
                print("JSON解析失败:", str(e))
        
        return ""
    except Exception as e:
        print("解析错误:", str(e))
        return ""

print("=== 测试响应1 ===")
result1 = extract_res_value_improved(response1.strip())
print("最终结果:", result1)

print("\n=== 测试响应2 ===")
result2 = extract_res_value_improved(response2.strip())
print("最终结果:", result2)
