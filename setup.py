from setuptools import setup, find_packages

setup(
    name="ibex",
    version="1.0",
    url="https://github.com/casterbyte/Ibex",
    author="Magama Bazarov",
    author_email="magamabazarov@mailbox.org",
    description="Pwning IPv6 Networks",
    long_description=open("README.md", encoding="utf8").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    keywords=[
        "pentesting", "mitm", "ipv6", "network security",
        "ipv6 attacks", "dns64", "nat64", "defensive", "offensive"
    ],
    packages=find_packages(),
    py_modules=["main"],
    install_requires=[
        "colorama",
        "netifaces",
        "scapy",
        "psutil"
    ],
    entry_points={
        "console_scripts": [
            "ibex = main:main"
        ]
    },
    python_requires='>=3.11',
)