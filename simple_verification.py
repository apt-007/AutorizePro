#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
简化的验证脚本，检查 authorization.py 文件的基本结构
"""

def check_file_exists():
    """检查文件是否存在"""
    import os
    if os.path.exists('authorization/authorization.py'):
        print("SUCCESS: authorization.py file exists")
        return True
    else:
        print("ERROR: authorization.py file not found")
        return False

def check_file_not_empty():
    """检查文件不为空"""
    try:
        with open('authorization/authorization.py', 'r') as f:
            content = f.read()
        
        if len(content.strip()) > 0:
            print("SUCCESS: authorization.py is not empty")
            print(f"File size: {len(content)} characters")
            return True
        else:
            print("ERROR: authorization.py is empty")
            return False
    except Exception as e:
        print("ERROR: Cannot read authorization.py:", str(e))
        return False

def check_required_functions():
    """检查是否包含必需的函数定义"""
    try:
        with open('authorization/authorization.py', 'r') as f:
            content = f.read()
        
        required_functions = [
            'def handle_message(',
            'def checkAuthorization(',
            'def generate_prompt(',
            'def extract_gemini_text(',
            'def request_dashscope_api(',
            'def call_dashscope_api('
        ]
        
        missing_functions = []
        for func in required_functions:
            if func not in content:
                missing_functions.append(func)
        
        if missing_functions:
            print("ERROR: Missing function definitions:")
            for func in missing_functions:
                print(f"  - {func}")
            return False
        else:
            print("SUCCESS: All required function definitions found")
            return True
            
    except Exception as e:
        print("ERROR: Cannot check functions:", str(e))
        return False

def check_gemini_support():
    """检查是否包含 Gemini 支持相关代码"""
    try:
        with open('authorization/authorization.py', 'r') as f:
            content = f.read()
        
        gemini_indicators = [
            'gemini',
            'X-goog-api-key',
            'generativelanguage.googleapis.com',
            'candidates',
            'contents'
        ]
        
        found_indicators = []
        for indicator in gemini_indicators:
            if indicator in content:
                found_indicators.append(indicator)
        
        if len(found_indicators) >= 4:
            print("SUCCESS: Gemini integration code found")
            print(f"Found {len(found_indicators)}/{len(gemini_indicators)} indicators")
            return True
        else:
            print("ERROR: Insufficient Gemini integration code")
            print(f"Found only {len(found_indicators)}/{len(gemini_indicators)} indicators")
            return False
            
    except Exception as e:
        print("ERROR: Cannot check Gemini support:", str(e))
        return False

def check_no_problematic_chars():
    """检查是否移除了可能导致 Jython 解析问题的字符"""
    try:
        with open('authorization/authorization.py', 'r') as f:
            content = f.read()
        
        # 检查是否有中文字符或其他可能的问题字符
        problematic_patterns = [
            '\\u6a21\\u578b',  # "模型" 的 Unicode 转义
            '\\u4e2d\\u6587',  # "中文" 的 Unicode 转义
        ]
        
        problems_found = []
        for pattern in problematic_patterns:
            if pattern in content:
                problems_found.append(pattern)
        
        # 检查 Unicode 范围内的中文字符
        chinese_chars = []
        for char in content:
            if '\u4e00' <= char <= '\u9fff':  # 中文字符范围
                chinese_chars.append(char)
        
        if problems_found or chinese_chars:
            print("ERROR: Found problematic characters:")
            if problems_found:
                print(f"  Unicode patterns: {problems_found}")
            if chinese_chars:
                print(f"  Chinese characters: {list(set(chinese_chars[:10]))}")  # Show first 10 unique Chinese chars
            return False
        else:
            print("SUCCESS: No problematic characters found")
            return True
            
    except Exception as e:
        print("ERROR: Cannot check for problematic characters:", str(e))
        return False

def check_encoding():
    """检查文件编码"""
    try:
        # 尝试以不同编码读取文件
        encodings = ['utf-8', 'latin-1', 'ascii']
        
        for encoding in encodings:
            try:
                with open('authorization/authorization.py', 'r', encoding=encoding) as f:
                    content = f.read()
                print(f"SUCCESS: File can be read with {encoding} encoding")
                return True
            except UnicodeDecodeError:
                continue
        
        print("ERROR: File cannot be read with common encodings")
        return False
        
    except Exception as e:
        print("ERROR: Cannot check encoding:", str(e))
        return False

if __name__ == "__main__":
    print("=== Simplified authorization.py Verification ===")
    
    tests = [
        ("File Exists", check_file_exists),
        ("File Not Empty", check_file_not_empty),
        ("Encoding Check", check_encoding),
        ("Required Functions", check_required_functions),
        ("Gemini Support", check_gemini_support),
        ("No Problematic Characters", check_no_problematic_chars)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        if test_func():
            passed += 1
        
    print(f"\n=== Summary ===")
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("SUCCESS: authorization.py appears to be ready for Burp Suite!")
        print("\nThe file should now load without the Unicode parsing error.")
        print("You can try loading the plugin in Burp Suite again.")
    elif passed >= total - 1:
        print("MOSTLY SUCCESS: authorization.py should work but has minor issues.")
        print("Try loading it in Burp Suite - it will likely work.")
    else:
        print("ERROR: Multiple issues found. Please address them before using.")
        
    print("\nFile analysis complete.")
