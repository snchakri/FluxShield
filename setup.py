from setuptools import setup, find_packages

setup(
    name="wafai",
    version="0.1.0",
    description="WAF AI - Web Application Firewall with AI capabilities",
    author="WAFAI Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "wafai=wafai.main:main",
        ],
    },
)
