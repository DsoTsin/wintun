import click

import pywintunx_pmd3
from pyuac import main_requires_admin


def log(level: int, timestamp: int, message: str) -> None:
    print(message)


@click.group()
def cli() -> None:
    """ Manage wintun driver """
    pass


@cli.command()
@main_requires_admin
def install() -> None:
    """ install wintun driver """
    pywintunx_pmd3.set_logger(log)
    pywintunx_pmd3.install_wetest_driver()


@cli.command()
@main_requires_admin
def uninstall() -> None:
    """ uninstall wintun driver """
    pywintunx_pmd3.set_logger(log)
    pywintunx_pmd3.uninstall_wetest_driver()
    pywintunx_pmd3.delete_driver()


@cli.command()
def version() -> None:
    """ show wintun driver version """
    pywintunx_pmd3.set_logger(log)
    print(pywintunx_pmd3.get_driver_version())


if __name__ == '__main__':
    cli()
