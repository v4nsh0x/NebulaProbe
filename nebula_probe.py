import argparse
import asyncio
import json
import os
import re
import socket
import time
from collections import OrderedDict

import aiodns
import requests
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)

BANNER = rf"""{Fore.CYAN}
  _   _      _ _       _             ____  _                        
 | \ | | ___| | | ___ | |__   ___   |  _ \| | __ _ _   _  ___ _ __  
 |  \| |/ _ \ | |/ _ \| '_ \ / _ \  | |_) | |/ _` | | | |/ _ \ '__| 
 | |\  |  __/ | | (_) | |_) |  __/  |  __/| | (_| | |_| |  __/ |    
 |_|\_\ \___|_|_|\___/|_.__/ \___|  |_|   |_|\__,_|\__, |\___|_|    
                                                  |___/            
{Fore.MAGENTA}       ☆  ☆    ☆       ☆    ☆      ☆    ☆  ☆  ☆
{Fore.YELLOW}     ☆       ☆     ☆        ☆    ☆     ☆     ☆
{Style.RESET_ALL}
"""

class NebulaProbe:
    def __init__(self, target, workers=50, wordlist=None, use_crt=True, do_bruteforce=False, output=None, verbose=False):
        self.target = target.strip().lower()
        self.base = re.sub(r"^\.*", "", self.target)
        self.workers = workers
        self.wordlist = wordlist
        self.use_crt = use_crt
        self.do_bruteforce = do_bruteforce
        self.output = output
        self.verbose = verbose
        self.found = OrderedDict()
        self.resolver = aiodns.DNSResolver()

    async def query_crtsh(self):
        url = f"https://crt.sh/?q=%25.{self.base}&output=json"
        headers = {"User-Agent": "Mozilla/5.0 (NebulaProbe)"}
        retries = 3
        for attempt in range(1, retries + 1):
            try:
                r = requests.get(url, timeout=20, headers=headers)
                if self.verbose:
                    print(Fore.CYAN + f"[debug] crt.sh HTTP {r.status_code} (attempt {attempt})" + Style.RESET_ALL)
                if r.status_code != 200:
                    if attempt < retries:
                        time.sleep(1 + attempt)
                        continue
                    return
                try:
                    data = r.json()
                except ValueError:
                    if self.verbose:
                        preview = (r.text[:500] + "...") if len(r.text) > 500 else r.text
                        print(Fore.YELLOW + "[debug] crt.sh response not JSON; preview:" + Style.RESET_ALL)
                        print(preview)
                    return
                if not isinstance(data, list) or not data:
                    if self.verbose:
                        print(Fore.YELLOW + "[debug] crt.sh returned empty list or unexpected structure." + Style.RESET_ALL)
                    return
                for entry in data:
                    name = entry.get("name_value")
                    if not name:
                        continue
                    for n in name.split("\n"):
                        host = n.strip().lower()
                        if host.endswith("."):
                            host = host[:-1]
                        if "*" in host:
                            continue
                        if host.endswith(self.base) and host not in self.found:
                            self.found[host] = None
                return
            except requests.RequestException as e:
                if self.verbose:
                    print(Fore.YELLOW + f"[debug] crt.sh request error: {e} (attempt {attempt})" + Style.RESET_ALL)
                if attempt < retries:
                    time.sleep(1 + attempt)
                    continue
                return

    async def resolve_host(self, host):
        try:
            resp = await self.resolver.gethostbyname(host, socket.AF_INET)
            ips = resp.addresses if hasattr(resp, "addresses") else [resp]
            return host, ips
        except Exception:
            try:
                loop = asyncio.get_running_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, host)
                return host, [ip]
            except Exception:
                return host, None

    async def resolve_all(self):
        tasks = []
        sem = asyncio.Semaphore(self.workers)

        async def runner(h):
            async with sem:
                return await self.resolve_host(h)

        for h in list(self.found.keys()):
            tasks.append(asyncio.ensure_future(runner(h)))

        results = []
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Resolving", unit="host"):
            try:
                res = await f
                results.append(res)
            except Exception:
                pass

        for host, ips in results:
            if ips:
                self.found[host] = ips

    def load_wordlist(self):
        if not self.wordlist:
            if self.verbose:
                print(Fore.YELLOW + "[info] no wordlist provided." + Style.RESET_ALL)
            return []
        path = os.path.expanduser(self.wordlist)
        if not os.path.isabs(path):
            path = os.path.join(os.getcwd(), path)
        if self.verbose:
            print(Fore.CYAN + f"[debug] resolved wordlist path: {path}" + Style.RESET_ALL)
        if not os.path.isfile(path):
            if self.verbose:
                print(Fore.YELLOW + f"[info] wordlist not found: {path}" + Style.RESET_ALL)
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                words = [w.strip() for w in fh if w.strip()]
        except Exception as e:
            if self.verbose:
                print(Fore.YELLOW + f"[info] error reading wordlist: {e}" + Style.RESET_ALL)
            return []
        if self.verbose:
            print(Fore.CYAN + f"[info] loaded {len(words)} words from {path}" + Style.RESET_ALL)
        return words

    async def bruteforce(self):
        words = self.load_wordlist()
        if not words:
            return
        queue = asyncio.Queue()
        for w in words:
            candidate = f"{w}.{self.base}"
            await queue.put(candidate)
        total = queue.qsize()
        if self.verbose:
            print(Fore.CYAN + f"[info] starting bruteforce: {total} candidates, {self.workers} workers" + Style.RESET_ALL)
        sem = asyncio.Semaphore(self.workers)

        async def worker_task(id):
            while True:
                try:
                    host = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                async with sem:
                    try:
                        resp = await self.resolver.gethostbyname(host, socket.AF_INET)
                        ips = resp.addresses if hasattr(resp, "addresses") else [resp]
                        if ips:
                            if host not in self.found:
                                self.found[host] = ips
                                if self.verbose:
                                    print(Fore.GREEN + f"[found] {host} -> {','.join(self.found[host])}" + Style.RESET_ALL)
                    except Exception:
                        try:
                            loop = asyncio.get_running_loop()
                            ip = await loop.run_in_executor(None, socket.gethostbyname, host)
                            if ip:
                                if host not in self.found:
                                    self.found[host] = [ip]
                                    if self.verbose:
                                        print(Fore.GREEN + f"[found-fallback] {host} -> {ip}" + Style.RESET_ALL)
                        except Exception:
                            pass
                queue.task_done()

        workers = [asyncio.create_task(worker_task(i)) for i in range(min(self.workers, max(2, total)))]
        await queue.join()
        for w in workers:
            w.cancel()

    def save(self):
        if not self.output:
            return
        name = self.output
        if name.endswith(".json"):
            j = [{"host": h, "ips": self.found[h]} for h in self.found]
            with open(name, "w", encoding="utf-8") as fh:
                json.dump(j, fh, indent=2)
            if self.verbose:
                print(Fore.CYAN + f"[info] saved {len(j)} entries to {name}" + Style.RESET_ALL)
            return
        with open(name, "w", encoding="utf-8") as fh:
            for h in self.found:
                line = h
                if self.found[h]:
                    line += " " + ",".join(self.found[h])
                fh.write(line + "\n")
        if self.verbose:
            print(Fore.CYAN + f"[info] saved {len(self.found)} entries to {name}" + Style.RESET_ALL)

    async def run(self):
        print(BANNER)
        if self.use_crt:
            await self.query_crtsh()
            if not self.found and self.verbose:
                print(Fore.YELLOW + "[info] crt.sh returned no entries or none matched." + Style.RESET_ALL)
        if self.do_bruteforce:
            await self.bruteforce()
        if self.found:
            await self.resolve_all()
        if self.found:
            print(Fore.GREEN + f"\nFound {len(self.found)} unique hosts for {self.base}" + Style.RESET_ALL)
            for h in self.found:
                ips = self.found[h]
                if ips:
                    print(Fore.YELLOW + h + Style.RESET_ALL + " -> " + ",".join(ips))
                else:
                    print(Fore.CYAN + h + Style.RESET_ALL + " -> unresolved")
        else:
            print(Fore.RED + "No hosts found." + Style.RESET_ALL)
        self.save()

def main():
    parser = argparse.ArgumentParser(prog="nebula-probe", description="NebulaProbe subdomain enumeration")
    parser.add_argument("--target", "-t", required=True)
    parser.add_argument("--workers", "-w", type=int, default=50)
    parser.add_argument("--wordlist", "-l")
    parser.add_argument("--crt", "-c", action="store_true")
    parser.add_argument("--bruteforce", "-b", action="store_true")
    parser.add_argument("--output", "-o")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    do_bruteforce_flag = args.bruteforce or bool(args.wordlist)
    nb = NebulaProbe(target=args.target, workers=args.workers, wordlist=args.wordlist,
                     use_crt=args.crt, do_bruteforce=do_bruteforce_flag, output=args.output,
                     verbose=args.verbose)

    try:
        asyncio.run(nb.run())
    except KeyboardInterrupt:
        print(Fore.RED + "\nExiting..." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
