#!/usr/bin/python

import click
import logging
import yaml
from subcommands.fetch_iocs import fetch_iocs
from subcommands.correlate import correlate
from subcommands.alert import alert
from subcommands.utils import make_sync


logger = logging.getLogger("unicorcli")

def configure(ctx, param, filename):
    # Parse config file
    try:
        with open(filename) as config_file:
            parsed_config = yaml.safe_load(config_file)
    except FileNotFoundError:
        logger.error("Configuration file %s not found. Exiting...", filename)
        exit(1)
    except:
        logger.error("Unexpected error while opening %s configuration file. Exiting...", filename)
        exit(1)

    ctx.default_map = parsed_config


@click.group()
@click.option(
    '-c', '--config',
    type         = click.Path(dir_okay=False, file_okay=True),
    default      = "/etc/unicor/config.yml",
    callback     = configure,
    is_eager     = True,
    expose_value = False,
    help         = 'Read option defaults from the specified yaml file',
    show_default = True,
)
@click.pass_context
def main(ctx,
    **kwargs
):
    ctx.ensure_object(dict)
    ctx.obj['CONFIG'] = ctx.default_map

    # Configure logging
    logging.basicConfig(
        level=ctx.obj['CONFIG']['logging_level'],
        format='%(asctime)s %(levelname)s:%(name)s:%(message)s'
    )
    pymisp_logger = logging.getLogger("pymisp")
#    pymisp_logger.setLevel(ctx.obj['CONFIG']['logging_level'])
    logging.getLogger('pymisp').setLevel(logging.WARNING)


main.add_command(correlate)
main.add_command(fetch_iocs)
main.add_command(alert)

if __name__ == "__main__":
    main()
