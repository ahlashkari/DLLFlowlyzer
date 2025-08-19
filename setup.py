from setuptools import setup, find_packages

setup(
    name="dllflowlyzer",
    version="1.0.0",
    description="DataLink Layer Network Flow Analyzer for extracting features from PCAP files",
    author="AmirHossein Ahmadnejad Roudsari",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "pandas>=1.5.0",
        "numpy>=1.21.0",
        "argparse",
        "configparser",
        "queue",
        "threading",
        "datetime",
        "pathlib",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "dllflowlyzer=src.flowlyzer.main:main",
        ],
    },
)