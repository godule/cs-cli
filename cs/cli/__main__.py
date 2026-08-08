from .cli.console import run_cli

if __name__ == "__main__":
    run_cli(__import__("sys").argv[1:])
