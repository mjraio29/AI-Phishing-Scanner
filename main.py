#!/usr/bin/env python3
"""
AI Phishing Scanner — CLI entry point
Usage:
    python main.py --email path/to/email.txt
    python main.py --url "https://example.com"
    python main.py --url "https://example.com" --no-llm
"""

import argparse
import sys
import json
from scanner.email_scanner import EmailScanner
from scanner.url_scanner import URLScanner


def print_result(result: dict, verbose: bool = False):
    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("score", 0.0)
    color = "\033[91m" if verdict == "PHISHING" else "\033[93m" if verdict == "SUSPICIOUS" else "\033[92m"
    reset = "\033[0m"

    print(f"\n{'='*50}")
    print(f"  Verdict : {color}{verdict}{reset}")
    print(f"  Score   : {score:.2f} / 1.00")
    print(f"  Target  : {result.get('target', 'N/A')}")
    print(f"{'='*50}")

    if verbose or verdict in ("PHISHING", "SUSPICIOUS"):
        print("\n[ML Features]")
        for k, v in result.get("ml_features", {}).items():
            print(f"  {k}: {v}")

        if result.get("llm_analysis"):
            print("\n[LLM Analysis]")
            print(f"  {result['llm_analysis']}")

        if result.get("flags"):
            print("\n[Flags]")
            for flag in result["flags"]:
                print(f"  • {flag}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="AI-powered phishing scanner using ML + LLM analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --url "http://paypa1-secure.com/login"
  python main.py --email samples/phish.txt
  python main.py --url "https://google.com" --no-llm --verbose
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", type=str, help="URL to scan")
    group.add_argument("--email", type=str, help="Path to email file (.txt or .eml)")

    parser.add_argument("--no-llm", action="store_true", help="Skip LLM analysis (faster, offline)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed feature breakdown")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()
    use_llm = not args.no_llm

    if args.url:
        scanner = URLScanner(use_llm=use_llm)
        result = scanner.scan(args.url)
    elif args.email:
        try:
            with open(args.email, "r", encoding="utf-8") as f:
                email_text = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.email}", file=sys.stderr)
            sys.exit(1)
        scanner = EmailScanner(use_llm=use_llm)
        result = scanner.scan(email_text)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_result(result, verbose=args.verbose)

    sys.exit(1 if result.get("verdict") in ("PHISHING", "SUSPICIOUS") else 0)


if __name__ == "__main__":
    main()
