from setuptools import setup, find_packages

def read_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip()]

setup(
    name='mitre-mcp',
    version='1.0.0',
    description='Threat intelligence framework with MITRE ATT&CK mapping',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    python_requires='>=3.8',
    install_requires=read_requirements(),
    license='MIT'
)
