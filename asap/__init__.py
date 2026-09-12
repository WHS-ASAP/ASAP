"""ASAP 3: passive Android static review. Never executes the target application."""
__version__ = "3.0.0"
RESEARCH_DATE = "2026-09-12"
CATEGORIES = (
    "SQL_Injection", "WebView", "DeepLink", "HardCoded", "Permission",
    "Insecure_DataStorage", "Insecure_Logging",
)
CATEGORY_ALIASES = {
    "Crypto": "Insecure_DataStorage", "LogE": "Insecure_Logging",
    "Hardcoded": "HardCoded", "SQLInjectionAnalyzer": "SQL_Injection",
    "WebViewAnalyzer": "WebView", "DeepLinkAnalyzer": "DeepLink",
    "HardCodedAnalyzer": "HardCoded", "PermissionAnalyzer": "Permission",
    "CryptoAnalyzer": "Insecure_DataStorage", "LogAnalyzer": "Insecure_Logging",
}
