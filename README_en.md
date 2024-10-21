![image](https://github.com/user-attachments/assets/e61f8069-f775-419d-b020-37d0f0ee1227)

# 🧿 AutorizePro (AI Analysis Module Now Available ❤️‍🔥):  Click star to support this project
### AutorizePro is a Burp plugin specialized in detecting privilege escalation, developed based on the Autorize plugin. It is easy to install and use.
> **⚠️ When the AI feature is not enabled, the plugin follows the normal detection logic. AI is optional. Since responses to APIs are typically varied, enabling AI analysis greatly improves detection accuracy. Highly recommended! Time is valuable, and we should let AI handle time-consuming and repetitive tasks whenever possible.**

### Tool Background
- **Privilege escalation vulnerabilities are almost always tested in black-box testing and SRC vulnerability hunting. However, manually testing for privilege escalation vulnerabilities one by one can be time-consuming, while automated tools often generate many false positives. AutorizePro was created to address this issue.**

### Tool Highlights
- **Optimized detection logic & added AI analysis module (optional), reducing the original tool's false-positive rate from 99% to 5%, freeing you from the sea of false positives.**
- **For alerts that require manual confirmation, the tool displays the original request, the privilege escalation request, and the unauthorized request in parallel, making it easier to compare differences.**

## 🔧 Installing AutorizePro
### 1️⃣ Download Burp Suite and Jython

    1. Download Burp Suite: https://portswigger.net/burp/releases
    2. Download the Jython standalone JAR file: https://www.jython.org/download.html

### 2️⃣ Configure Burp Suite’s Python Environment

	1. Open Burp Suite.
	2. Navigate to Extender -> Options.
	3. In the Python Environment section, click Select File.
	4. Choose the Jython standalone JAR file you just downloaded (tested with version 2.7.3).

### 3️⃣ Install the AutorizePro Plugin
	1. Download the plugin to your local machine.
    2. Open Burp Suite, navigate to Extender -> Extensions -> Add.
    3. In the Extension Type dropdown, select python.
    4. In the Extension File field, choose the path to the `AutorizePro.py` file from the repository.

### AutorizePro Plugin Successfully Installed 🎉
> 💡 The display ratio between the display page and the configuration page can be adjusted by pulling the sidebar in the middle (the full-screen display is basically normal, but when the screen is small (non-full-screen or laptop), only the display page may be seen, and the configuration page can be displayed by pulling the sidebar to the left, for subsequent optimization).

![cover](imgs/cover.png)

## 🔫 Using the AutorizePro Plugin
    1. Open the configuration tab by clicking AutorizePro -> Configuration.

    2. Use the `fetch cookie header` button to fetch the latest authentication header from the request or manually copy the low-privileged user's authentication header (usually Cookie or Authorization), then paste it into the textbox labeled “Insert injected header here.” Note: If the request already contains the header, the plugin will replace it; otherwise, a new header will be added.

    3. If you don’t need to test unauthenticated requests (i.e., requests without any cookies to check if the endpoint requires authentication), you can uncheck the `Check unauthenticated` box (enabled by default).

    4. Enable the `Intercept requests from Repeater` checkbox to process requests sent from Repeater with the plugin.

    5. Click the `AutorizePro is off` button to enable the plugin, allowing AutorizePro to start intercepting traffic and performing authorization checks.

    6. Open your browser and configure proxy settings to direct traffic through Burp's proxy.

    7. Use a high-privileged user account to access the application you want to test. When modifying resources for the privilege escalation test, you can use the Match/Replace configuration to modify the resource information needed for the test.

    8. In the left-side results panel of the AutorizePro plugin, you will see the URL of the request and the corresponding privilege check status.

    9. Currently, only the Aliyun Tongyi Qianwen API key (starting with `sk`) is supported. How to obtain the API key: https://help.aliyun.com/zh/model-studio/developer-reference/get-api-key.

    10. When the API key is enabled, requests that meet the AI analysis trigger conditions will be further analyzed by AI, and results will be displayed in the `AI Analyzer` column.

    11. By clicking a URL in the left-side results panel, you can view its original request, modified request, and unauthenticated request/response to help distinguish differences.

### 🌠 Example Usage Effect
> 🌟 Drastically reduced false positives: As seen in the image below, after enabling AI analysis, you only need to analyze whether a request is truly unauthorized, saving over 95% of manual analysis effort.

![eg](imgs/eg.png)
> View the specific request determined by AI to be unauthorized, and simultaneously display the unauthorized request, original request, and unauthenticated request to easily compare differences.

![response](imgs/response.png)

### ❓ Status Explanation
- **Bypassed! (Red) : Unauthorized Access Detected**
- **Enforced! (Green) : No Unauthorized Access Detected**
- **Is enforced??? (please configure enforcement detector): Cannot Determine, Configure Enforcement Detector for Assistance**

```angular2html
TIPS:
The `Is enforced???` status means the plugin cannot determine if the endpoint is enforcing authorization. You can configure the enforcement detector with specific authorization characteristics to assist in judgment.

Example:
If a particular endpoint responds with “Unauthorized” for privilege escalation attempts, you can add this fingerprint to the Enforcement Detector filter. This way, the plugin will look for this characteristic when judging if authorization is enforced, reducing false positives.
```

### 🚰 Filter Configuration: Set Interception Rules in Interception Filters

- **You can configure which domains or which requests the plugin should intercept.**
- **Filters can be based on blacklists, whitelists, regular expressions, or Burp’s scope settings, preventing unnecessary domains from being intercepted, reducing irrelevant request analysis.**
- **🌟 The default configuration avoids intercepting scripts and images, but you can add more static resource types to the ignore list.**

## 💰 How Much Does the AI Analysis Feature Cost? (By default, detection logic is followed, and AI is only activated when enabled by the user)
- To minimize the costs associated with AI analysis, only packets with equal status codes, JSON format responses, and lengths under 3000 are analyzed when AI analysis is enabled. If conditions are not met, AI analysis will not activate.  
- ⚠️ Note: When enabling AI analysis, you should configure the intercepted domains/rules in Interception Filters to avoid cost overruns caused by analyzing irrelevant sites.
- The AI analysis feature requires activating the model service on [Aliyun Bailian](https://bailian.console.aliyun.com/#/home) via the prompt at the top of the page:
![tongyi](imgs/tongyi.png)
- [Aliyun Tongyi Qianwen API Billing Explanation](https://help.aliyun.com/zh/model-studio/billing-for-model-studio) (Personal testing cost example: during high-frequency testing throughout a full day without domain restrictions, the total cost was **¥0.38**; actual costs are halved for production models, with faster speeds).
<p>
    <img alt="AIFee" src="https://suleo.wang/img/AutorizePro/ai_fee.jpg" width="30%" height="30%" style="max-width:20%;">
</p>

## ⛪ Discussion
* Bug reports or feature suggestions [Click Here](https://github.com/sule01u/AutorizePro/issues)
* PRs Welcome
* WeChat Public Account: **Scan to follow Bù Dǒng Ānquán for more security insights**
<p>
    <img alt="QR-code" src="https://suleo.wang/img/mine.png" width="30%" height="30%" style="max-width:20%;">
</p>

## 🤗 Acknowledgments
**This product is developed based on the [Autorize](https://github.com/Quitten/Autorize) plugin. Thanks to Barak Tawily.**

## 📑 Licenses

The following disclaimer is added in addition to the original agreement. If there is a conflict with the original agreement, the disclaimer takes precedence.

<u>When using this tool for detection, you must ensure that the behavior complies with local laws and regulations, and you have obtained sufficient authorization. Unauthorized penetration testing is prohibited. Unauthorized penetration testing after secondary development is also prohibited.

If any illegal activity occurs during the use of this tool, you will be solely responsible for the consequences. The developer will not bear any legal or joint liability.</u>

Before using this tool, you must carefully read and fully understand the terms. Limitations, disclaimers, or other clauses involving significant rights and interests may be highlighted with bold or underlined text to draw your attention. Unless you have fully read, understood, and accepted all the terms of this agreement, please do not use this tool. Your use or any other express or implied acceptance of this agreement means you have read and agreed to be bound by its terms.
