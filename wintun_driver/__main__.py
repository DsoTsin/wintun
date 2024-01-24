import click

import pywintun_pmd3
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
    pywintun_pmd3.set_logger(log)
    pywintun_pmd3.install_wetest_driver()


@cli.command()
@main_requires_admin
def uninstall() -> None:
    """ uninstall wintun driver """
    pywintun_pmd3.set_logger(log)
    pywintun_pmd3.delete_driver()


@cli.command()
def version() -> None:
    """ show wintun driver version """
    pywintun_pmd3.set_logger(log)
    print(pywintun_pmd3.get_driver_version())


if __name__ == '__main__':
    cli()
