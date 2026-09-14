from src.cli.main import parser
def test_cli_parse():
 assert parser().parse_args(['assess','192.168.56.101']).command=='assess'
 assert parser().parse_args(['scan','nmap','192.168.56.101']).subcommand=='nmap'
 assert parser().parse_args(['target','add','192.168.56.101']).subcommand=='add'
