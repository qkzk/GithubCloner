#!/usr/bin/env python3

from dataclasses import dataclass

import argparse
import json
import os
import queue
import threading
import time

import git
import requests


class ConfigError(Exception):
    """Exception for configuration validation errors."""

    pass


@dataclass
class Config:
    users: str
    organizations: str
    include_organization_members: bool
    output_path: str
    threads_limit: int
    authentication: str
    include_authenticated_repos: bool
    include_gists: bool
    echo_urls: bool
    prefix_mode: str
    api_prefix: str
    exclude_repos: str
    owner_only: bool
    exclude_forked: bool

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Config":
        users = args.users if args.users else None
        organizations = args.organizations if args.organizations else None
        include_organization_members = (
            args.include_organization_members
            if args.include_organization_members
            else False
        )
        output_path = args.output_path if args.output_path else "."
        threads_limit = int(args.threads_limit) if args.threads_limit else 5
        authentication = args.authentication if args.authentication else None
        include_authenticated_repos = (
            args.include_authenticated_repos
            if args.include_authenticated_repos
            else False
        )
        include_gists = args.include_gists if args.include_gists else False
        echo_urls = args.echo_urls if args.echo_urls else False
        prefix_mode = args.prefix_mode
        api_prefix = args.api_prefix
        exclude_repos = args.exclude_repos if args.exclude_repos else None
        owner_only = args.owner_only if args.owner_only else False
        exclude_forked = args.exclude_forked if args.exclude_forked else False
        return cls(
            users,
            organizations,
            include_organization_members,
            output_path,
            threads_limit,
            authentication,
            include_authenticated_repos,
            include_gists,
            echo_urls,
            prefix_mode,
            api_prefix,
            exclude_repos,
            owner_only,
            exclude_forked,
        )

    def validate(self) -> "Config":
        """
        Validates the configuration. Raises ConfigurationError if any validation fails.
        Returns the validated Config object.
        """
        self.validate_threads_limit()
        self.validate_output_path()
        self.validate_github_targets()
        self.validate_threads_limit_type()
        self.validate_output_directory()
        self.validate_authentication()
        self.validate_authenticated_repos_flag()
        self.validate_prefix_mode()
        return self

    def validate_threads_limit(self) -> None:
        """Validates that the thread limit does not exceed 10."""
        if self.threads_limit > 10:
            raise ConfigError(
                "Using more than 10 threads may cause errors. "
                "Decrease the number of threads."
            )

    def validate_output_path(self) -> None:
        """Ensures an output path is specified if URLs are not echoed."""
        if not self.output_path and not self.echo_urls:
            raise ConfigError("The output path is not specified.")

    def validate_github_targets(self) -> None:
        """Validates that at least one of GitHub users or organizations is specified."""
        if not (self.users or self.organizations):
            raise ConfigError(
                "Both GitHub users and GitHub organizations must be specified."
            )

    def validate_threads_limit_type(self) -> None:
        """Ensures the thread limit is a valid digit."""
        if not str(self.threads_limit).isdigit():
            raise ConfigError("Specified threads limit is invalid.")

    def validate_output_directory(self) -> None:
        """Checks if the output directory exists or creates it if necessary."""
        if not self.echo_urls:
            try:
                if not os.path.exists(self.output_path):
                    os.mkdir(self.output_path)
            except Exception as error:
                raise ConfigError(f"Error creating the output directory: {repr(error)}")

    def validate_authentication(self) -> None:
        """Validates and processes authentication credentials."""
        if self.authentication is not None:
            if ":" not in self.authentication:
                raise ConfigError(
                    "Incorrect authentication value. Must be: "
                    "<username>:<password_or_personal_access_token>"
                )
            username, token = self.authentication.split(":", 1)
            if not GetReposURLs(
                self.api_prefix, self.exclude_repos
            ).check_authentication(username, token):
                raise ConfigError("Authentication failed.")
            self.username = username
            self.token = token
        else:
            self.username = None
            self.token = None

    def validate_authenticated_repos_flag(self) -> None:
        """
        Ensures the --include-authenticated-repos flag is only used
        if authentication is provided.
        """
        if self.include_authenticated_repos and self.authentication is None:
            raise ConfigError(
                "--include-authenticated-repos is used but --authentication is not provided."
            )

    def validate_prefix_mode(self) -> None:
        """Validates the prefix mode value."""
        if self.prefix_mode not in ["none", "underscore", "directory"]:
            raise ConfigError(
                'prefix_mode must be one of: "none", "underscore", "directory".'
            )


class Driver:
    def __init__(self, config: Config) -> None:
        self.config = config

    def authenticated_repos(self) -> list:
        if self.config.token is None or self.config.username is None:
            raise ValueError("token and username can't be None")

        return GetReposURLs(
            self.config.api_prefix, self.config.exclude_repos
        ).from_authenticated_user(
            self.config.username,
            self.config.token,
            self.config.exclude_forked,
            self.config.owner_only,
        )

    def authenticated_user(self, user: str) -> list:
        return GetReposURLs(
            self.config.api_prefix, self.config.exclude_repos
        ).from_user(
            user,
            username=self.config.username,
            token=self.config.token,
            include_gists=self.config.include_gists,
            exclude_forked=self.config.exclude_forked,
            owner_only=self.config.owner_only,
        )

    def organization_members(self, organization: str) -> list:
        return GetReposURLs(self.config.api_prefix, self.config.exclude_repos).from_org(
            organization,
            username=self.config.username,
            token=self.config.token,
            exclude_forked=self.config.exclude_forked,
        )

    def org_include_users(self, organization: str) -> list:
        return GetReposURLs(
            self.config.api_prefix, self.config.exclude_repos
        ).from_org_include_users(
            organization,
            username=self.config.username,
            token=self.config.token,
            include_gists=self.config.include_gists,
            exclude_forked=self.config.exclude_forked,
        )

    def dedup_sort(self, urls: list) -> list:
        urls = list(set(urls))
        urls.sort()
        return urls

    def print_urls(self, urls: list) -> None:
        for url in urls:
            print(
                parse_git_url(
                    url, username=self.config.username, token=self.config.token
                )
            )
        return

    def sync_urls(self, urls: list) -> None:
        Cloner(
            urls,
            self.config.output_path,
            threads_limit=self.config.threads_limit,
            username=self.config.username,
            token=self.config.token,
            prefix_mode=self.config.prefix_mode,
        ).clone_bulk_repos()

    def build_urls(self) -> list:
        urls = []
        if (
            self.config.include_authenticated_repos
            and self.config.username is not None
            and self.config.token is not None
            and self.config.owner_only is not None
        ):
            urls.extend(self.authenticated_repos())

        if self.config.users is not None and self.config.owner_only is not None:
            users = self.config.users.replace(" ", "").split(",")
            for user in users:
                urls.extend(self.authenticated_user(user))

        if self.config.organizations is not None:
            organizations = self.config.organizations.replace(" ", "").split(",")

            for organization in organizations:
                if self.config.include_organization_members is False:
                    urls.extend(self.organization_members(organization))
                else:
                    urls.extend(self.org_include_users(organization))
        return urls

    def sync(self):
        urls = self.build_urls()
        urls = self.dedup_sort(urls)
        if self.config.echo_urls:
            self.print_urls(urls)
        self.sync_urls(urls)


class GetReposURLs:
    def __init__(self, api_prefix: str, exclude_repos: str = None):
        """
        Initialize the class with the API prefix and optional excluded repositories.
        """
        self.user_agent = "GithubCloner (https://github.com/mazen160/GithubCloner)"
        self.headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        self.timeout = 30
        self.api_prefix = api_prefix
        self.excluded_repos_list = (
            [] if exclude_repos is None else exclude_repos.strip().split(",")
        )

    def _filter_excluded_repos(self, url: str) -> bool:
        """
        Returns True if the URL does not match any excluded repositories.
        """
        return not any(excluded in url for excluded in self.excluded_repos_list)

    def _fetch_paginated_data(
        self, api_url: str, username: str = None, token: str = None
    ) -> list[dict]:
        """
        Fetches paginated data from a GitHub API endpoint.
        """
        data = []
        current_page = 1

        while True:
            url = f"{api_url}&page={current_page}"
            response = self._make_request(url, username, token)
            if not response:
                break
            data.extend(response)
            current_page += 1

        return data

    def _make_request(
        self, url: str, username: str = None, token: str = None
    ) -> list[dict]:
        """
        Makes an API request and returns the JSON response.
        """
        auth = (username, token) if username and token else None
        response = requests.get(
            url, headers=self.headers, timeout=self.timeout, auth=auth
        )
        return json.loads(response.text)

    def _append_urls(
        self,
        urls: list,
        data: list[dict],
        key: str,
        exclude_forked: bool = False,
        owner: str = None,
    ):
        """
        Appends URLs to the list based on filtering criteria.
        """
        for item in data:
            if exclude_forked and item.get("fork", False):
                continue
            if owner and item.get("owner", {}).get("login") != owner:
                continue
            url = item.get(key)
            if url and self._filter_excluded_repos(url):
                urls.append(url)

    def _check_response(self, response: dict) -> int:
        """
        Validates the API response and checks for errors.
        """
        if "message" in response:
            if "API rate limit exceeded" in response["message"]:
                print("[!] Error: GitHub API rate limit exceeded")
                return 1
            if response["message"] == "Not Found":
                return 2  # The organization does not exist
        return 0

    def from_user(
        self,
        user: str,
        username: str = None,
        token: str = None,
        include_gists: bool = False,
        exclude_forked: bool = False,
        owner_only: bool = False,
    ) -> list:
        """
        Retrieves repository URLs for a user, optionally including gists.
        """
        urls = []
        api_url = f"{self.api_prefix}/users/{user}/repos?per_page=100"
        data = self._fetch_paginated_data(api_url, username, token)
        owner = username if owner_only else None

        self._append_urls(urls, data, "git_url", exclude_forked, owner)

        if include_gists:
            urls.extend(self.user_gists(user, username, token, owner_only))
        return urls

    def from_org(
        self,
        org_name: str,
        username: str = None,
        token: str = None,
        exclude_forked: bool = False,
        owner_only: bool = False,
    ) -> list:
        """
        Retrieves repository URLs for an organization.
        """
        urls = []
        api_url = f"{self.api_prefix}/orgs/{org_name}/repos?per_page=100"
        data = self._fetch_paginated_data(api_url, username, token)
        owner = username if owner_only else None

        self._append_urls(urls, data, "git_url", exclude_forked, owner)
        return urls

    def user_gists(
        self,
        user: str,
        username: str = None,
        token: str = None,
        owner_only: bool = False,
    ) -> list:
        """
        Retrieves gist URLs for a user.
        """
        urls = []
        api_url = f"{self.api_prefix}/users/{user}/gists?per_page=100"
        data = self._fetch_paginated_data(api_url, username, token)
        owner = username if owner_only else None

        self._append_urls(urls, data, "git_pull_url", owner=owner)
        return urls

    def from_authenticated_user(
        self,
        username: str,
        token: str,
        exclude_forked: bool = False,
        owner_only: bool = False,
    ) -> list:
        """
        Retrieves repository URLs accessible by an authenticated user.
        """
        urls = []
        api_url = f"{self.api_prefix}/user/repos?per_page=100&type=all"
        data = self._fetch_paginated_data(api_url, username, token)
        owner = username if owner_only else None

        self._append_urls(urls, data, "git_url", exclude_forked, owner)
        return urls

    def from_org_include_users(
        self,
        org_name: str,
        username: str = None,
        token: str = None,
        include_gists: bool = False,
        exclude_forked: bool = False,
    ) -> list:
        """
        Retrieves repository URLs for an organization and its members.
        """
        urls = self.from_org(org_name, username, token, exclude_forked)
        api_url = f"{self.api_prefix}/orgs/{org_name}/members?per_page=100"
        members = self._fetch_paginated_data(api_url, username, token)

        for member in members:
            member_login = member.get("login")
            if member_login:
                urls.extend(
                    self.from_user(
                        member_login, username, token, include_gists, exclude_forked
                    )
                )
        return urls

    def check_authentication(self, username: str, token: str) -> bool:
        """
        Verifies if the provided credentials are valid.
        """
        api_url = f"{self.api_prefix}/user"
        response = requests.get(
            api_url, auth=(username, token), headers=self.headers, timeout=self.timeout
        )
        return response.status_code == 200


class Cloner:
    def __init__(
        self,
        urls: list,
        cloning_path: str,
        threads_limit: int = 5,
        username: str = None,
        token: str = None,
        prefix_mode: str = "underscore",
    ):
        self.urls = urls
        self.cloning_path = cloning_path
        self.threads_limit = threads_limit
        self.username = username
        self.token = token
        self.prefix_mode = prefix_mode

    def clone_bulk_repos(self):
        """
        Clones a bulk of GIT repositories.
        Input:-
        URLs: A list of GIT repository URLs.
        cloningPath: the directory that the repository will be cloned at.
        Optional Input:-
        threads_limit: The limit of working threads.
        username: Github username.
        token: Github token or password.
        """

        q = queue.Queue()
        for url in self.urls:
            q.put(url)

        threads_state: list[threading.Thread] = []
        while not q.empty():
            task = q.get()
            t = self.build_thread(
                task,
            )
            if threading.active_count() < self.threads_limit + 1:
                t.start()
                threads_state.append(t)
            else:
                time.sleep(0.5)

        for t in threads_state:
            if t.is_alive:
                t.join()

    def get_repopath(self, repo_username: str, repo_name: str):
        """
        Returns a string of the repo path.
        """
        repopath = ""
        if self.prefix_mode == "none":
            repopath = repo_name
        elif self.prefix_mode == "underscore":
            repopath = repo_username + "_" + repo_name
        elif self.prefix_mode == "directory":
            repopath = repo_username + "/" + repo_name
        else:
            raise ValueError("Unknown prefix_mode %s", self.prefix_mode)

        repopath = repopath.strip(".git")
        if "@" in repopath:
            repopath = repopath.replace(repopath[: repopath.index("@") + 1], "")
        return repopath

    def create_dirs(self, url: str):
        try:
            if not os.path.exists(self.cloning_path):
                os.mkdir(self.cloning_path)
            if self.prefix_mode == "directory":
                repo_username = url.split("/")[-2]
                if not os.path.exists(self.cloning_path + "/" + repo_username):
                    os.mkdir(self.cloning_path + "/" + repo_username)
        except Exception:
            print("Error: There is an error in creating directories")

    @staticmethod
    def username_name(url: str) -> tuple[str, str]:
        splits = url.split("/")
        return (splits[-2], splits[-1])

    def clone_repo(
        self,
        url: str = "",
    ):
        """
        Clones a single GIT repository.
        Input:-
        URL: GIT repository URL.
        cloningPath: the directory that the repository will be cloned at.
        Optional Input:-
        username: Github username.
        token: Github token or password.
        """

        try:
            self.create_dirs(url)
            url = parse_git_url(url, username=self.username, token=self.token)
            repo_username, repo_name = self.username_name(url)
            repopath = self.get_repopath(repo_username, repo_name)

            fullpath = self.cloning_path + repopath
            with threading.Lock():
                print(fullpath)

            if os.path.exists(fullpath):
                git.Repo(fullpath).remote().pull()
            else:
                git.Repo.clone_from(url, fullpath)
        except Exception as e:
            print(e)
            print(f"Error: There was an error in cloning [{url}]")

    def build_thread(
        self,
        task: str,
    ) -> threading.Thread:
        return threading.Thread(
            target=self.clone_repo,
            args=(task,),
            daemon=True,
        )


def parse_git_url(url, username: str = None, token: str = None) -> str:
    """
    This function parses the GIT URL.
    """

    url = url.replace("git://", "https://")
    if (username or token) is not None:
        url = url.replace("https://", "https://{0}:{1}@".format(username, token))
    return url


def parse_args() -> argparse.Namespace:
    """
    Parses the user-inputted arguments from stdin and returns a Namespace.
    """
    parser = argparse.ArgumentParser()

    # fmt: off
    arguments = [
        {"flags": ["-u", "--user"], "dest": "users", "help": "GitHub user (comma-separated for multiple users)."},
        {"flags": ["-org", "--org"], "dest": "organizations", "help": "GitHub organization (comma-separated for multiple organizations)."},
        {"flags": ["--include-org-members"], "dest": "include_organization_members", "help": "Include the members of a GitHub organization.", "action": "store_true"},
        {"flags": ["-o", "--output-path"], "dest": "output_path", "help": "Directory to clone Git repositories."},
        {"flags": ["-t", "--threads"], "dest": "threads_limit", "help": "Threads used in cloning repositories (Default: 5).", "default": 5},
        {"flags": ["-a", "--authentication"], "dest": "authentication", "help": "GitHub authentication credentials (username:token)."},
        {"flags": ["--include-authenticated-repos"], "dest": "include_authenticated_repos", "help": "Include repositories the authenticated GitHub account has access to.", "action": "store_true"},
        {"flags": ["--include-gists"], "dest": "include_gists", "help": "Include gists.", "action": "store_true"},
        {"flags": ["--echo-urls"], "dest": "echo_urls", "help": "Print gathered URLs only and then exit.", "action": "store_true"},
        {"flags": ["--prefix-mode"], "dest": "prefix_mode", "help": "Sets the prefix mode for the repo directory (none, underscore, directory).", "default": "underscore"},
        {"flags": ["--api-prefix"], "dest": "api_prefix", "help": "GitHub Enterprise domain to prefix to API calls.", "default": "https://api.github.com"},
        {"flags": ["--exclude-repos"], "dest": "exclude_repos", "help": "Comma-separated list of repos to exclude: 'repo1,repo2,...'"},
        {"flags": ["--exclude-forked"], "dest": "exclude_forked", "help": "Exclude forked repositories.", "action": "store_true"},
        {"flags": ["--owner-only"], "dest": "owner_only", "help": "Exclude repositories you don't own.", "action": "store_true"},
    ]
    # fmt: on

    for arg in arguments:
        parser.add_argument(*arg.pop("flags"), **arg)

    return parser.parse_args()


def main():
    """
    The main function.
    1. parse the arguments and send it as argument to config,
    2. validate the config send it as argument to driver,
    3. sync the driver.
    """
    Driver(Config.from_args(parse_args()).validate()).sync()


if __name__ == "__main__":
    main()
