from setuptools import setup, find_packages
import sys
import platform
import os

def get_data_files():
    files = []
    if sys.platform.startswith('linux'):
        files.extend([
            ('share/applications', ['zloblocker/zloblocker.desktop']),
            ('share/icons/hicolor/scalable/apps', ['zloblocker/zloblocker.svg']),
            ('share/pixmaps', ['zloblocker/zloblocker.svg'])
        ])
        if 'astra' in platform.platform().lower():
            files.extend([
                ('share/applications/flydesktop', ['zloblocker/zloblocker.desktop']),
                ('usr/share/applications/flystartmenu', ['zloblocker/zloblocker.desktop']),
                ('usr/share/applications', ['zloblocker/zloblocker.desktop']),
                ('usr/share/icons/hicolor/scalable/apps', ['zloblocker/zloblocker.svg']),
                ('usr/share/pixmaps', ['zloblocker/zloblocker.svg'])
            ])
    return files

setup(
    name="zloblocker",
    version="1.0",
    packages=find_packages(),
    install_requires=['requests>=2.25.0', 'urllib3>=2.0.0'],
    extras_require={
        'windows': ['pywin32>=228', 'PySide2>=5.15.0'],
        'linux': ['PySide2>=5.15.0']
    },
    entry_points={
        'gui_scripts': [
            'zloblocker=zloblocker.main:main',
        ],
    },
    package_data={
        "zloblocker": ["main.ui", "zloblocker.desktop", "zloblocker.svg"],
    },
    data_files=get_data_files(),
    author="Алексей Черемных",
    author_email="info@mrkaban.ru",
    description="Блокировщик нежелательных хостов",
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: X11 Applications :: Qt',
        'Intended Audience :: End Users/Desktop',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3',
        'Topic :: Internet',
        'Topic :: Security',
    ]
)
