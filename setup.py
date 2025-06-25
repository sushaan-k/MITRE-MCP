from setuptools import setup

setup(
    name='mitre-mcp',
    version='1.0.0',
    description='Threat intelligence framework with MITRE ATT&CK mapping',
    py_modules=['mcp_server', 'models', 'mitre_attack', 'threat_analyzer', 'web_interface'],
    python_requires='>=3.8',
    install_requires=[
        'fastapi>=0.104.1',
        'uvicorn>=0.24.0',
        'pydantic>=2.5.0',
        'requests>=2.31.0',
        'jinja2>=3.1.2'
    ],
    license='MIT'
)
