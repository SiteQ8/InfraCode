from setuptools import setup, find_packages

setup(
    name="infracode",
    version="1.0.0",
    author="Ali AlEnezi",
    author_email="Site@hotmail.com",
    description="Infrastructure as Code Platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/SiteQ8/InfraCode",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "pyyaml>=6.0",
        "cryptography>=41.0",
    ],
    extras_require={
        "api": ["fastapi>=0.104.0", "uvicorn>=0.24.0"],
        "aws": ["boto3>=1.29.0"],
        "azure": ["azure-identity>=1.15.0"],
        "gcp": ["google-auth>=2.23.0"],
        "k8s": ["kubernetes>=28.1.0"],
        "dev": ["pytest>=7.4.0", "black>=23.0", "ruff>=0.1.0"],
    },
    entry_points={
        "console_scripts": [
            "infracode=cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Systems Administration",
    ],
)
