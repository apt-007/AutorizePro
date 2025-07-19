#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
验证修复后的 authorization.py 文件
"""

def test_import():
    """测试导入 authorization 模块"""
    try:
        from authorization.authorization import handle_message
        print("SUCCESS: handle_message function imported successfully")
        return True
    except Exception as e:
        print("ERROR: Failed to import handle_message:", str(e))
        return False

def test_syntax():
    """测试文件语法"""
    try:
        import ast
        
        with open('authorization/authorization.py', 'r') as f:
            content = f.read()
        
        # 解析 AST
        ast.parse(content)
        print("SUCCESS: authorization.py syntax is valid")
        return True
    except SyntaxError as e:
        print("ERROR: Syntax error in authorization.py:", str(e))
        return False
    except Exception as e:
        print("ERROR: Failed to parse authorization.py:", str(e))
        return False

def test_functions_exist():
    """测试关键函数是否存在"""
    try:
        from authorization import authorization
        
        required_functions = [
            'handle_message',
            'checkAuthorization', 
            'checkBypass',
            'generate_prompt',
            'extract_gemini_text',
            'request_dashscope_api'
        ]
        
        missing_functions = []
        for func_name in required_functions:
            if not hasattr(authorization, func_name):
                missing_functions.append(func_name)
        
        if missing_functions:
            print("ERROR: Missing functions:", ", ".join(missing_functions))
            return False
        else:
            print("SUCCESS: All required functions exist")
            return True
            
    except Exception as e:
        print("ERROR: Failed to verify functions:", str(e))
        return False

def test_gemini_integration():
    """测试 Gemini 集成相关功能"""
    try:
        from authorization import authorization
        
        # 创建一个模拟的 self 对象来测试函数
        class MockSelf:
            pass
        
        mock_self = MockSelf()
        
        # 测试 generate_prompt 函数对 Gemini 的支持
        system_prompt = "You are a security analyst"
        user_prompt = "Analyze the responses"
        
        result = authorization.generate_prompt(mock_self, "gemini-1.5-flash", system_prompt, user_prompt)
        
        if "contents" in result and "parts" in result:
            print("SUCCESS: Gemini prompt generation works")
            return True
        else:
            print("ERROR: Gemini prompt generation failed")
            return False
            
    except Exception as e:
        print("ERROR: Gemini integration test failed:", str(e))
        return False

if __name__ == "__main__":
    print("=== Verifying Fixed authorization.py ===")
    
    tests = [
        ("Syntax Check", test_syntax),
        ("Import Test", test_import),
        ("Functions Check", test_functions_exist),
        ("Gemini Integration", test_gemini_integration)
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
        print("SUCCESS: authorization.py is ready for Burp Suite!")
        print("\nNext steps:")
        print("1. Load the plugin in Burp Suite")
        print("2. Configure Gemini API key in the extension settings")
        print("3. Select a Gemini model (gemini-1.5-flash, gemini-1.5-pro, etc.)")
        print("4. Enable AI analysis and test the functionality")
    else:
        print("ERROR: Some tests failed. Please check the issues above.")
