from setuptools import setup

setup(
    name='solo-cli',
    version='0.9a1',
    description='Bracket Computing Solo command line interface',
    url='http://brkt.com',
    license='Apache 2.0',
    packages=['solo_cli'],
    install_requires=['boto'],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'brkt = solo_cli:main',
        ]
    },
    test_suite='test'
)
