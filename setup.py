from setuptools import setup, find_packages

setup(
    name="sara",
    version="1.3",
    url="https://github.com/caster0x00/Sara",
    author="Magama Bazarov",
    author_email="magamabazarov@mailbox.org",
    scripts=['sara.py'],
    description="RouterOS Security Inspector",
    long_description=open('README.md', encoding="utf8").read(),
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    keywords=['mikrotik', 'routeros', 'config analyzer', 'network security', 'cve',],
    packages=find_packages(),
    install_requires=[
        'colorama',
        'netmiko',
        'packaging',
        'requests',
    ],
    py_modules=['cve_analyzer'],
    entry_points={
        "console_scripts": ["sara = sara:main"],
    },
    python_requires='>=3.11',
)