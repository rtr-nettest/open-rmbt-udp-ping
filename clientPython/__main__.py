from argparse import ArgumentParser

from .client import PingClient


def main() -> None:
    parser = ArgumentParser(description="UDP Ping Client with HMAC-SHA256 validation")
    parser.add_argument("--host", required=True, help="Hostname of the server")
    parser.add_argument("--port", type=int, default=444, help="Server port (default: 444)")
    parser.add_argument("--seed", help="Seed for HMAC computation")
    parser.add_argument("--ip", help="Source IP for HMAC calculation")
    parser.add_argument("--token", help="Base64 encoded pre-computed token")
    args = parser.parse_args()

    if args.token and (args.seed or args.ip):
        parser.error("--token cannot be used with --seed or --ip")
    if not args.token and not (args.seed and args.ip):
        parser.error("either --token or both --seed and --ip are required")

    PingClient(
        args.host,
        args.port,
        seed=args.seed,
        source_ip=args.ip,
        token=args.token,
    ).run()


if __name__ == '__main__':
    main()
