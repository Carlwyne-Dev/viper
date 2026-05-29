from setuptools import setup, find_packages

setup(
    name="viper-cli",
    version="0.2.0",
    description="Viper — we bite. A personal recon & security toolkit.",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
    ],
    extras_require={
        "full": ["dnspython", "python-whois"]
    },
    entry_points={
        "console_scripts": ["viper=viper.cli:cli"],
    },
)
