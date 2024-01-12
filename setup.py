from setuptools import setup, Extension

setup(name='pywintun_pmd3',
      author='zq2024',
      author_email='dsotsen@gmail.com',
      maintainer='zq2024',
      maintainer_email='dsotsen@gmail.com',
      url='https://github.com/dsotsin/wintun',
      description='wintun (WireGuard) wrapper for Python',
      long_description=open('PyReadMe.md').read(),
      version='0.0.1',
      ext_modules=[
          Extension('pywintun_pmd3', sources=[
                'api/pybinding.c',
                'api/resource.c',
                'api/resources.rc'
            ],
            define_macros=[
                ('WITH_PYTHON', 1),
                ('MONOLITHIC_BUILD', 1),
                ('WINTUN_VERSION_MAJ', '0'),
                ('WINTUN_VERSION_MIN', '14'),
                ('WINTUN_VERSION_REL', '1')
            ],
#            extra_compile_args=[
#                "/Zi"
#            ],
            extra_link_args=[
#                "/DEBUG",
                "/DYNAMICBASE",
                "Cfgmgr32.lib",
                "Iphlpapi.lib",
                "onecore.lib",
                "version.lib",
                "delayimp.lib",
                "swdevice.lib",
                "ntdll.lib",
                "api/nci.lib",
                "/DELAYLOAD:advapi32.dll",
                "/DELAYLOAD:shell32.dll",
                "/DELAYLOAD:api-ms-win-devices-query-l1-1-0.dll",
                "/DELAYLOAD:api-ms-win-devices-swdevice-l1-1-0.dll",
                "/DELAYLOAD:cfgmgr32.dll",
                "/DELAYLOAD:iphlpapi.dll",
                "/DELAYLOAD:nci.dll",
            ])
        ],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: Microsoft :: Windows',
          'Programming Language :: C',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking'])