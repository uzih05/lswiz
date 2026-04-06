from setuptools import setup, find_packages

setup(
    name='lswiz',
    version='0.1.0',
    description='CentOS 7 EOL security vulnerability scanner and risk scoring CLI tool',
    author='Yu Jiheon',
    author_email='luv.wlgjs@gmail.com',
    url='https://github.com/uzih05/lswiz',
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=[
        'requests>=2.18',
        'PyYAML>=3.12',
    ],
    entry_points={
        'console_scripts': [
            'lswiz=lswiz.cli:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Topic :: Security',
    ],
)
