from setuptools import setup

def read_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip()]

setup(
    name='mitre-mcp',
    version='1.0.0',
    description='Threat intelligence framework with MITRE ATT&CK mapping',
    packages=['src'],
    package_dir={'src': 'src'},
    py_modules=[
        'src.mcp_server',
        'src.web_interface',
        'src.threat_analyzer',
        'src.mitre_attack',
        'src.models'
    ],
    python_requires='>=3.8',
    install_requires=read_requirements(),
    license='MIT',
    entry_points={
        'console_scripts': [
            'mitre-mcp=src.mcp_server:main',
            'mitre-web=src.web_interface:main',
        ],
    },
)
