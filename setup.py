#!/usr/bin/env python3
"""
Setup script for MCP Threat Intelligence Framework
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    with open(readme_path, 'r', encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    with open(req_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='mcp-threat-intelligence-framework',
    version='1.0.0',
    description='AI-powered threat intelligence analysis with automated MITRE ATT&CK mapping',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='AI Security Framework Team',
    author_email='security@ai-framework.org',
    url='https://github.com/ai-security/mcp-threat-intelligence',
    license='MIT',
    
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    
    python_requires='>=3.8',
    install_requires=read_requirements(),
    
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
    ],
    
    keywords=[
        'cybersecurity',
        'threat-intelligence',
        'mitre-attack',
        'ai-agent',
        'mcp',
        'security-analysis',
        'ioc-extraction',
        'risk-assessment'
    ],
    
    entry_points={
        'console_scripts': [
            'mcp-threat-server=mcp_server:main',
            'mcp-threat-web=web_interface:main',
            'mcp-threat-demo=working_demo:demonstrate_framework',
            'mcp-threat-test=production_tests:main',
        ],
    },
    
    package_data={
        '': ['*.md', '*.txt', '*.json', '*.html'],
        'data': ['*.db'],
        'templates': ['*.html'],
    },
    
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-asyncio>=0.21.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.0.0',
        ],
        'web': [
            'jinja2>=3.1.0',
            'aiofiles>=23.0.0',
        ],
        'monitoring': [
            'prometheus-client>=0.19.0',
            'structlog>=23.0.0',
        ],
    },
    
    project_urls={
        'Documentation': 'https://ai-security.github.io/mcp-threat-intelligence/',
        'Source': 'https://github.com/ai-security/mcp-threat-intelligence',
        'Tracker': 'https://github.com/ai-security/mcp-threat-intelligence/issues',
        'Funding': 'https://github.com/sponsors/ai-security',
    },
    
    zip_safe=False,
)
