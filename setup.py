from setuptools import setup, find_packages

setup(
    name="sichgate",
    version="0.2.0",
    author="SichGate CLI",
    description="AI security auditing tool for startups",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "sichgate=sichgate.cli:main",
        ],
    },
)