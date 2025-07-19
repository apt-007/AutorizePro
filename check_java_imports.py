#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
检查 Java 导入是否正确
"""

def check_java_imports():
    """检查 Java 导入是否符合 Jython 要求"""
    
    # 正确的 Java 导入映射
    correct_imports = {
        'EOFException': 'java.io',
        'SocketException': 'java.net',
        'URL': 'java.net',
        'HttpURLConnection': 'java.net',
        'OutputStreamWriter': 'java.io',
        'BufferedReader': 'java.io',
        'InputStreamReader': 'java.io',
        'SSLSocketFactory': 'javax.net.ssl',
        'SSLHandshakeException': 'javax.net.ssl',
        'SwingUtilities': 'javax.swing',
        'StringBuilder': 'java.lang',
        'Runnable': 'java.lang'
    }
    
    try:
        with open('authorization/authorization.py', 'r') as f:
            content = f.read()
        
        print("=== Java Import Analysis ===")
        
        # 检查每个导入
        import_issues = []
        
        for class_name, expected_package in correct_imports.items():
            # 检查是否在正确的包中导入
            correct_import = f"from {expected_package} import"
            if class_name in content:
                if correct_import in content and class_name in content.split(correct_import)[1].split('\n')[0]:
                    print(f"✅ {class_name}: correctly imported from {expected_package}")
                else:
                    # 检查是否在错误的包中导入
                    wrong_import_found = False
                    for line in content.split('\n'):
                        if f"import" in line and class_name in line and expected_package not in line:
                            print(f"❌ {class_name}: incorrectly imported in line: {line.strip()}")
                            import_issues.append(f"{class_name} should be from {expected_package}")
                            wrong_import_found = True
                            break
                    
                    if not wrong_import_found:
                        print(f"⚠️  {class_name}: used in code but import not found")
        
        # 检查是否有重复导入
        import_lines = [line.strip() for line in content.split('\n') if line.strip().startswith('from java') or line.strip().startswith('from javax')]
        unique_imports = set(import_lines)
        
        if len(import_lines) != len(unique_imports):
            print(f"\n❌ Found duplicate imports:")
            for imp in import_lines:
                if import_lines.count(imp) > 1:
                    print(f"  - {imp} (appears {import_lines.count(imp)} times)")
            import_issues.append("Duplicate imports found")
        else:
            print(f"\n✅ No duplicate imports found")
        
        print(f"\n=== Import Summary ===")
        if import_issues:
            print(f"❌ Issues found: {len(import_issues)}")
            for issue in import_issues:
                print(f"  - {issue}")
            return False
        else:
            print(f"✅ All Java imports appear correct")
            return True
            
    except Exception as e:
        print(f"ERROR: Cannot analyze imports: {e}")
        return False

def check_class_usage():
    """检查类的使用是否正确"""
    try:
        with open('authorization/authorization.py', 'r') as f:
            content = f.read()
        
        print(f"\n=== Class Usage Analysis ===")
        
        # 检查常见的类使用问题
        issues = []
        
        # 检查 UpdateTableEDT 类是否正确继承
        if 'class UpdateTableEDT(java.lang.Runnable):' in content:
            issues.append("UpdateTableEDT should use imported Runnable, not java.lang.Runnable")
        elif 'class UpdateTableEDT(Runnable):' in content:
            print("✅ UpdateTableEDT correctly inherits from Runnable")
        else:
            issues.append("UpdateTableEDT class definition not found or incorrect")
        
        if issues:
            print(f"❌ Class usage issues:")
            for issue in issues:
                print(f"  - {issue}")
            return False
        else:
            print(f"✅ Class usage appears correct")
            return True
            
    except Exception as e:
        print(f"ERROR: Cannot analyze class usage: {e}")
        return False

if __name__ == "__main__":
    print("=== Java Import Verification for Jython ===")
    
    import_ok = check_java_imports()
    class_ok = check_class_usage()
    
    print(f"\n=== Final Result ===")
    if import_ok and class_ok:
        print("✅ SUCCESS: All Java imports and usage appear correct for Jython")
        print("The plugin should now load properly in Burp Suite")
    else:
        print("❌ ISSUES FOUND: Please fix the above issues before loading in Burp Suite")
