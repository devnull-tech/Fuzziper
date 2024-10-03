import argparse
from fuzzer import Fuzzer
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description='Fuzziper V1.0 By Leandro Puentes Rivas (lpuentesrivas@gmail.com)')
    parser.add_argument('action', type=str, help='Action (FUZZ, READ)')
    parser.add_argument('--url', '-u', type=str, help='Target Base URL for FUZZ action')
    parser.add_argument('--input', '-i', type=str, help='Input file (previus Fuzziper output) for READ action')
    parser.add_argument('--filter_code', '-fc', default="404",type=str, help='Filter by status code (404,500) for READ action (404 by default)')
    parser.add_argument('--method', '-m', default="GET", type=str, help='Fuzzing method (GET by default)')
    parser.add_argument('--wordlist', '-w', type=str, help='Wordlist PATH')
    parser.add_argument('--threads', '-t', default=10, type=int, help='Threads (10 by default)')
    parser.add_argument('--output', '-o', default="fuzziper.txt", type=str, help='Output name (fuzziper.txt by default)')
    args = parser.parse_args()

    if args.action == "FUZZ" and not (args.url and args.wordlist):
        parser.error("The --wordlist and --url arguments are required when the action is 'FUZZ'.")
    if args.action == "READ" and not args.input:
        parser.error("The --input argument are required when the action is 'READ'.")

    if args.action.lower() == "fuzz":
        print("[+] Fuzziper starting at - " + str(datetime.now()))
        fuzzer = Fuzzer(args.wordlist, args.threads)
        fuzzer.deploy_fuzz(args.url, args.method)
        fuzzer.export_output(args.output)
        print("[+] Fuzziper end at - " + str(datetime.now()))
    if args.action.lower() == "read":
        reader = Fuzzer("", read_mode=True)
        reader.input_from_file(args.input)
        filter_status = args.filter_code.split(',')
        filter_status_list = [int(code) for code in filter_status]
        print(Fuzzer.get_printable(reader.filter_status(filter_status_list)))

if __name__ == '__main__':
    main()
