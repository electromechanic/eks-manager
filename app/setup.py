from setuptools import setup, find_packages

setup(
    name="eks-manager",
    version="0.2.0",
    description="A CLI tool for managing EKS clusters",
    author="my name",
    author_email="your.email@example.com",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click",
        "boto3",
        "PyYAML",
    ],
    entry_points={
        "console_scripts": ["eks=eks:cli", "eks-manager=eks:cli"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Unix",
    ],
    python_requires=">=3.6",
)
