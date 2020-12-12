#!/usr/bin/env python3
import argparse
import requests
import sys
import subprocess
import os
import gzip
import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass


GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')


# Manually merged:
# https://cwe.mitre.org/data/definitions/658.html
# https://cwe.mitre.org/data/definitions/659.html
CWE_MAP = {
    "CWE-14": "Compiler Removal of Code to Clear Buffers",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-123": "Write-what-where Condition",
    "CWE-124": "Buffer Underwrite ('Buffer Underflow')",
    "CWE-125": "Out-of-bounds Read",
    "CWE-126": "Buffer Over-read",
    "CWE-127": "Buffer Under-read",
    "CWE-128": "Wrap-around Error",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-130": "Improper Handling of Length Parameter Inconsistency",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-135": "Incorrect Calculation of Multi-Byte String Length",
    "CWE-170": "Improper Null Termination",
    "CWE-188": "Reliance on Data/Memory Layout",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-192": "Integer Coercion Error",
    "CWE-194": "Unexpected Sign Extension",
    "CWE-195": "Signed to Unsigned Conversion Error",
    "CWE-196": "Unsigned to Signed Conversion Error",
    "CWE-197": "Numeric Truncation Error",
    "CWE-242": "Use of Inherently Dangerous Function",
    "CWE-243": "Creation of chroot Jail Without Changing Working Directory",
    "CWE-244": "Improper Clearing of Heap Memory Before Release ('Heap Inspection')",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    "CWE-364": "Signal Handler Race Condition",
    "CWE-365": "Race Condition in Switch",
    "CWE-366": "Race Condition within a Thread",
    "CWE-374": "Passing Mutable Objects to an Untrusted Method",
    "CWE-375": "Returning a Mutable Object to an Untrusted Caller",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-460": "Improper Cleanup on Thrown Exception",
    "CWE-462": "Duplicate Key in Associative List (Alist)",
    "CWE-463": "Deletion of Data Structure Sentinel",
    "CWE-464": "Addition of Data Structure Sentinel",
    "CWE-466": "Return of Pointer Value Outside of Expected Range",
    "CWE-467": "Use of sizeof() on a Pointer Type",
    "CWE-468": "Incorrect Pointer Scaling",
    "CWE-469": "Use of Pointer Subtraction to Determine Size",
    "CWE-474": "Use of Function with Inconsistent Implementations",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-478": "Missing Default Case in Switch Statement",
    "CWE-479": "Signal Handler Use of a Non-reentrant Function",
    "CWE-480": "Use of Incorrect Operator",
    "CWE-481": "Assigning instead of Comparing",
    "CWE-482": "Comparing instead of Assigning",
    "CWE-483": "Incorrect Block Delimitation",
    "CWE-484": "Omitted Break Statement in Switch",
    "CWE-495": "Private Data Structure Returned From A Public Method",
    "CWE-496": "Public Data Assigned to Private Array-Typed Field",
    "CWE-558": "Use of getlogin() in Multithreaded Application",
    "CWE-560": "Use of umask() with chmod-style Argument",
    "CWE-562": "Return of Stack Variable Address",
    "CWE-587": "Assignment of a Fixed Address to a Pointer",
    "CWE-676": "Use of Potentially Dangerous Function",
    "CWE-685": "Function Call With Incorrect Number of Arguments",
    "CWE-688": "Function Call With Incorrect Variable or Reference as Argument",
    "CWE-689": "Permission Race Condition During Resource Copy",
    "CWE-690": "Unchecked Return Value to NULL Pointer Dereference",
    "CWE-704": "Incorrect Type Conversion or Cast",
    "CWE-733": "Compiler Optimization Removal or Modification of Security-critical Code",
    "CWE-762": "Mismatched Memory Management Routines",
    "CWE-781": "Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code",
    "CWE-782": "Exposed IOCTL with Insufficient Access Control",
    "CWE-783": "Operator Precedence Logic Error",
    "CWE-785": "Use of Path Manipulation Function without Maximum-sized Buffer",
    "CWE-787": "Out-of-bounds Write",
    "CWE-789": "Uncontrolled Memory Allocation",
    "CWE-805": "Buffer Access with Incorrect Length Value",
    "CWE-806": "Buffer Access Using Size of Source Buffer",
    "CWE-839": "Numeric Range Comparison Without Minimum Check",
    "CWE-843": "Access of Resource Using Incompatible Type ('Type Confusion')",
    "CWE-910": "Use of Expired File Descriptor",
    "CWE-911": "Improper Update of Reference Count",
    # C++ specific
    "CWE-248": "Uncaught Exception",
    "CWE-396": "Declaration of Catch for Generic Exception",
    "CWE-397": "Declaration of Throws for Generic Exception",
    "CWE-493": "Critical Public Variable Without Final Modifier",
    "CWE-498": "Cloneable Class Containing Sensitive Information",
    "CWE-500": "Public Static Field Not Marked Final",
    "CWE-543": "Use of Singleton Pattern Without Synchronization in a Multithreaded Context",
    "CWE-766": "Critical Data Element Declared Public",
    "CWE-767": "Access to Critical Private Variable via Public Method",
}


@dataclass
class CVEInfo:
    cve_id: str
    cwe_id: str
    description: str


@dataclass
class FileInfo:
    """Information about the changed file received through Github API.

    Args:
        filename: A relative path to file (e.g. src/Core/main.c)
        patch: A complete diff with changes
        github_url: The Raw URL of the corresponding version of this file on Github
    """
    filename: str
    patch: str
    github_url: Optional[str]


@dataclass
class GithubRepository:
    url: str
    user: str
    repo: str
    commit_hash: Optional[str]
    commit_url: Optional[str]
    other_urls: List[str]
    changed_files: List[FileInfo]
    language: str
    cve: CVEInfo


def print_cve_summary_plain(repo: GithubRepository, print_commands: bool):
    print(f'{repo.cve.cve_id} (https://nvd.nist.gov/vuln/detail/{repo.cve.cve_id})')
    if CWE_MAP.get(repo.cve.cwe_id):
        print(f'Bugtype:     {CWE_MAP[repo.cve.cwe_id]} ({repo.cve.cwe_id})')
    else:
        print(f'Bugtype:      {repo.cve.cwe_id}')
    print(f'Language:     {repo.language}')
    print(f'Description:  {repo.cve.description}')
    if repo.commit_url:
        print(f'Fix commit:   {repo.commit_url}')
    if print_commands:
        print('Commands to start bughunting:')
        if repo.commit_hash:
            print(f' git clone {repo.url[:-1]}.git')
            name = repo.url.split('/')[-2]
            print(f' cd {name}')
            print(f' git reset --hard {repo.commit_hash} # fixed')
            print(f' git reset --hard HEAD^1 # vulnerable')
        for f in repo.changed_files:
            print(f' cppcheck --bug-hunting {f.filename}')
    print()


def print_cve_summary_html(repo: GithubRepository, print_commands: bool):
    print(f'<details>')
    print(f'<summary>{repo.cve.cve_id} ({repo.user}/{repo.repo})</summary>')
    print(f'<table>')
    print(f'<tr><td>NVD URL</td>')
    print(f'<td>https://nvd.nist.gov/vuln/detail/{repo.cve.cve_id}</td></tr>')
    print(f'<tr><td>Bugtype</td>')
    print(f'<td><a href=https://cwe.mitre.org/data/definitions/{repo.cve.cwe_id[4:]}.html>{repo.cve.cwe_id}')
    print(f'</a></td>')
    print(f'<tr><td>Language</td><td>{repo.language}</td></tr>')
    print(f'<tr><td>Description</td><td>{repo.cve.description}</td></tr>')
    if repo.commit_url:
        print(f'<tr><td>Fix commit</td><td><a href={repo.commit_url}>{repo.commit_hash}</a></td></tr>')
    print('</table>')
    if print_commands:
        print('<p>Commands to start bughunting:</p>')
        print('<p><pre>')
        if repo.commit_hash:
            print(f' git clone {repo.url[:-1]}.git')
            name = repo.url.split('/')[-2]
            print(f' cd {name}')
            print(f' git reset --hard {repo.commit_hash} # fixed')
            print(f' git reset --hard HEAD^1 # vulnerable')
        for f in repo.changed_files:
            print(f' cppcheck --bug-hunting {f.filename}')
        print('</pre></p>')
    print(f'<p>Patch contents:</p>')
    for f in repo.changed_files:
        print(f'<p><a href={f.github_url}>{f.filename}:</a></p>')
        print(f'<pre>{f.patch}</pre>')
    print(f'</details>')
    print('<hr>')


class CVEParser:

    commit_hash_re = re.compile(
        r'^https?://github\.com/([a-zA-Z0-9_\-]+)/([a-zA-Z0-9_\-]+)/commit/(?P<commit>[a-zA-Z0-9]+)')
    user_repo_re = re.compile(
        r'^https?://github\.com/(?P<user>[a-zA-Z0-9_\-]+)/(?P<repo>[a-zA-Z0-9_\-]+)/')

    def __init__(self, name='nvdcve-1.1-2020', download=True):
        self.cve_items: List[Dict[str, str]
                             ] = self.fetch_cve_items(name, download)

    def fetch_cve_items(self, name: str, download: bool) -> List[Dict[str, str]]:
        if download:
            url = f'https://nvd.nist.gov/feeds/json/cve/1.1/{name}.json.gz'
            try:
                r = requests.get(url, allow_redirects=True)
            except requests.exceptions.RequestException:
                return {}
            with open(f'{name}.json.gz', 'wb') as f:
                f.write(r.content)
        with gzip.open(f'{name}.json.gz', 'rb') as f:
            return json.loads(f.read().decode('utf-8')).get("CVE_Items", {})
        return {}

    def iter_repositories(self, wanted_cwe_id:str):
        # FIXME: This is getting somewhat clumsy. It will probably be better to use jq.
        for item in self.cve_items:
            cve = item.get('cve')
            if not cve:
                continue

            # Parse CVE information
            data_meta = cve.get('CVE_data_meta')
            if not data_meta:
                continue
            cve_id = data_meta.get('ID')
            if not cve_id:
                continue
            description = cve.get('description')
            if not description:
                continue
            description_data = description.get('description_data')
            if not description_data or len(description_data) < 1:
                continue
            description_value = description_data[0].get('value')
            if not description_value:
                continue

            # Parse CWE number if exists
            cwe_id = 'Unknown'
            pt = cve.get('problemtype')
            if pt:
                pt_data = pt.get('problemtype_data')
                if pt_data and len(pt_data) >= 1:
                    pt_description = pt_data[0].get('description')
                    if pt_description and len(pt_description) >= 1:
                        cwe_id = pt_description[0].get('value', 'Unknown')

            if wanted_cwe_id and cwe_id != wanted_cwe_id:
                continue

            cve_obj = CVEInfo(cve_id=cve_id, cwe_id=cwe_id, description=description_value)

            # Parse information about the repository
            refs = cve.get('references')
            if not refs:
                continue
            refs = refs.get('reference_data')
            if not refs:
                continue
            # Here could be link to commit, issue or PR
            commit_url = ''
            commit_hash = ''
            other_urls = []
            for ref in refs:
                url = ref.get('url')
                if not url:
                    continue
                m_commit = re.search(self.commit_hash_re, url)
                if m_commit:
                    commit_hash = m_commit.groupdict().get('commit')
                    commit_url = url
                else:
                    other_urls.append(url)

            # Filter only supported C/C++ repositories
            repo = self.get_repository(commit_url, commit_hash, other_urls, cve_obj)
            if repo:
                self.fetch_commit_info(repo)
                repo.cve_id = cve_id
                yield repo

    def get_repository(self, commit_url: str, commit_hash: str,
                       other_urls: List[str], cve: CVEInfo):
        user = ''
        repo = ''
        for url in [commit_url] + other_urls:
            m = re.search(self.user_repo_re, url)
            if not m:
                return
            user = m.groupdict().get('user')
            repo = m.groupdict().get('repo')
            if user and repo:
                break
        if not user or not repo:
            return

        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        response = requests.get(url=f"https://api.github.com/repos/{user}/{repo}",
                                headers=headers)
        json = response.json()
        if not json:
            return
        if 'message' in json and json['message'] == 'Not Found':
            return
        if 'language' in json:
            language = json['language']
            if language and language in ('C', 'C++'):
                return GithubRepository(url=f"https://github.com/{user}/{repo}/",
                                        user=user, repo=repo,
                                        commit_hash=commit_hash,
                                        commit_url=commit_url,
                                        other_urls=other_urls,
                                        changed_files=[],
                                        language=language, cve=cve)
        return None

    def fetch_commit_info(self, repo) -> bool:
        if not repo or not repo.commit_hash:
            return False
        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        response = requests.get(url=f"https://api.github.com/repos/{repo.user}/{repo.repo}/commits/{repo.commit_hash}",
                                headers=headers)
        json = response.json()
        if not json:
            return False
        files = json.get('files')
        if not files:
            return False
        for file in files:
            filename = file.get('filename')
            patch = file.get('patch')
            raw_url = file.get('raw_url')
            repo.changed_files.append(FileInfo(filename, patch, raw_url))
        return True


class BugFinder:

    def __init__(self, repo: GithubRepository,
                 download_path='/tmp',
                 cppcheck_bin='cppcheck'):
        self.cppcheck_bin = cppcheck_bin
        self.repo = repo
        self.download_path = download_path
        self.repo_path = f"{self.download_path}/{self.repo.repo}"

    def clone_repo(self) -> bool:
        p = subprocess.Popen(['git', 'clone', repo.url],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             cwd=self.download_path)
        p.wait()
        return p.returncode == 0

    def reset_repo(self) -> bool:
        p = subprocess.Popen(['git', 'reset', '--hard', self.repo.commit_hash],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             cwd=self.repo_path)
        p.wait()
        return p.returncode == 0

    def do_check(self) -> None:
        # Save git diff with the bug fix
        with open(f'{self.repo.repo}.diff', "wb") as f:
            p = subprocess.Popen(['git', 'diff', 'HEAD~1'],
                                 stdout=f,
                                 stderr=subprocess.STDOUT,
                                 cwd=self.repo_path)
            p.wait()

        # Run Cppcheck in each of the modified files
        for file in self.get_changed_files():
            with open(f'{self.repo.repo}.diff', "wb") as f:
                repo_path = f"{self.download_path}/{self.repo.repo}"
                p = subprocess.Popen([self.cppcheck_bin, '--bug-hunting', file],
                                     stdout=f,
                                     stderr=subprocess.STDOUT,
                                     cwd=repo_path)
                p.wait()

    def get_changed_files(self) -> List[str]:
        out = subprocess.check_output(['git', 'diff-tree', '--no-commit-id',
                                       '--name-only', '-r',
                                       self.repo.commit_hash],
                                      cwd=self.repo_path)
        return out.decode("utf-8").splitlines()

    def clean_repo(self) -> bool:
        p = subprocess.Popen(['rm', '-rf', self.repo.repo],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             cwd=self.download_path)
        p.wait()
        return p.returncode == 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--clone", action="store_true",
                        help="Clone and reset repositories to the commit that fixes CVE.")
    parser.add_argument("-C", "--clean", action="store_true",
                        help="Remove cloned repositories after the check.")
    parser.add_argument("-s", "--start-cppcheck", action="store_true",
                        help="Start Cppcheck in bughunting mode on the repositories.")
    parser.add_argument("-f", "--format", type=str, default='plain',
                        help="Output format (plain|html)")
    parser.add_argument("--cwe", type=str, default=None,
                        help="List specified CWE only")
    args = parser.parse_args()

    if not GITHUB_TOKEN:
        print('Please set GITHUB_TOKEN environment variable')
        sys.exit(1)

    if args.start_cppcheck and not args.clone:
        args.clone = True

    parser = CVEParser(download=True)
    for repo in parser.iter_repositories(args.cwe):
        bf = BugFinder(repo)
        changed_files = []
        if args.clone:
            bf.clone_repo()
            bf.reset_repo()

        if args.format == 'plain':
            print_cve_summary_plain(repo, not args.start_cppcheck)
        else:
            print_cve_summary_html(repo, not args.start_cppcheck)

        if args.start_cppcheck:
            bf.do_check()
        if args.clean:
            bf.clean_repo()
