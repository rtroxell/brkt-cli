from setuptools import setup

setup(
    name='brkt-cli',
    version='0.9a1',
    description='Bracket Computing command line interface',
    url='http://brkt.com',
    license='Apache 2.0',
    packages=['brkt_cli'],
    install_requires=['boto'],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'brkt = brkt_cli:main',
        ]
    },
    test_suite='test'
)
