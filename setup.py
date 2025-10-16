import os
from setuptools import (
    find_packages,
    setup,
)

version = {}
with open("./oidc_provider/version.py") as fp:
    exec(fp.read(), version)

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='senzil-django-oidc-provider',
    version=version['__version__'],
    packages=find_packages(),
    include_package_data=True,
    license='MIT License',
    description='OpenID Connect Provider implementation for Django.',
    long_description='http://github.com/senzil/senzil-django-oidc-provider',
    url='http://github.com/senzil/senzil-django-oidc-provider',
    author='Juan Ignacio Fiorentino',
    author_email='juanifioren@gmail.com',
    zip_safe=False,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Framework :: Django',
        'Framework :: Django :: 3.2',
        'Framework :: Django :: 4.0',
        'Framework :: Django :: 4.1',
        'Framework :: Django :: 4.2',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Security',
    ],
    test_suite='runtests.runtests',
    tests_require=[
        'authlib>=1.3.0',
        'pytest>=7.4.0',
        'pytest-django>=4.5.0',
    ],

    install_requires=[
        'Django>=3.2',
        'authlib>=1.3.0',
        'cryptography>=41.0.0',
        'pycryptodomex>=3.19.0',
    ],
)
