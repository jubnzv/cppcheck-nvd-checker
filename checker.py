#!/usr/bin/env python3
import requests
import sys
import subprocess
import os
import gzip
import json
import re
from typing import Dict, List
from dataclasses import dataclass


GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')


@dataclass
class GithubRepository:
    url: str
    user: str
    repo: str
    commit_hash: str
    cve_id: str


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

    def iter_repositories(self):
        for item in self.cve_items:
            cve = item.get('cve')
            if not cve:
                continue

            # Get CVE number
            data_meta = cve.get('CVE_data_meta')
            if not data_meta:
                continue
            cve_id = data_meta.get('ID')
            if not cve_id:
                continue

            # Get information about the repository
            refs = cve.get('references')
            if not refs:
                continue
            ref = refs.get('reference_data')
            if not ref or len(ref) < 1:
                continue
            url = ref[0].get('url')
            if not url:
                continue

            # Filter only supported C/C++ repositories
            repo = self.get_repository(url)
            if repo:
                repo.cve_id = cve_id
                yield repo

    def get_repository(self, url: str):
        m = re.search(self.user_repo_re, url)
        if not m:
            return
        user = m.groupdict().get('user')
        repo = m.groupdict().get('repo')
        if not user or not repo:
            return

        m_commit = re.search(self.commit_hash_re, url)
        if not m_commit:
            return
        commit = m_commit.groupdict().get('commit')
        if not commit:
            return

        headers = {'Authorization': 'token %s' % GITHUB_TOKEN}
        response = requests.get(url="https://api.github.com/repos/%s/%s" % (user, repo),
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
                                        user=user, repo=repo, commit_hash=commit, cve_id='')
        return None


class BugFinder:

    def __init__(self, repo: GithubRepository, download_path='/tmp', cppcheck_bin='cppcheck'):
        self.cppcheck_bin = cppcheck_bin
        self.repo = repo
        self.download_path = download_path

    def clone_repo(self):
        p = subprocess.Popen(['git', 'clone', repo.url],
                             cwd=self.download_path)
        p.wait()
        if p.returncode != 0:
            print(f"{self.repo.url}: git clone failed with rc={p.returncode}")
            return

    def do_check(self):
        repo_path = f"{self.download_path}/{self.repo.repo}"
        p = subprocess.Popen(['git', 'reset', '--hard', self.repo.commit_hash],
                             cwd=repo_path)
        p.wait()
        if p.returncode != 0:
            print(f"git reset failed (rc={p.returncode})")
            return

        # Show git diff for the bug fix
        print('-------------------')
        repo_path = f"{self.download_path}/{self.repo.repo}"
        p = subprocess.Popen(['git', 'diff', 'HEAD~1'],
                             cwd=repo_path)
        p.wait()
        print('-------------------')

        for f in self.get_changed_files(repo_path, self.repo.commit_hash):
            repo_path = f"{self.download_path}/{self.repo.repo}"
            p = subprocess.Popen([self.cppcheck_bin, '--bug-hunting', f],
                                 cwd=repo_path)
            p.wait()

    def get_changed_files(self, repo_path, commit_hash) -> List[str]:
        out = subprocess.check_output(['git', 'diff-tree', '--no-commit-id', '--name-only', '-r', commit_hash],
                                      cwd=repo_path)
        return out.decode("utf-8").splitlines()

    def clean_repo(self):
        p = subprocess.Popen(['rm', '-rf', self.repo.repo],
                             cwd=self.download_path)
        p.wait()
        rc = p.returncode
        if rc != 0:
            print(
                f"Can't remove directory {self.download_path}/{self.repo.repo} (rc={rc})")
            return


if __name__ == '__main__':
    if not GITHUB_TOKEN:
        print('Please set GITHUB_TOKEN environment variable')
        sys.exit(1)

    parser = CVEParser()
    for repo in parser.iter_repositories():
        print(repo)
        bf = BugFinder(repo)
        bf.clone_repo()
        bf.do_check()
        # bf.clean_repo()
