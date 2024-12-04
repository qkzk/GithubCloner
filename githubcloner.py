#!/usr/bin/env python3

import json
import os
import queue
import threading
import time
import argparse

from dataclasses import dataclass

import git
import requests


class GetReposURLs:
    def __init__(self, api_prefix: str, exclude_repos: str | None = None):
        self.user_agent = "GithubCloner (https://github.com/mazen160/GithubCloner)"
        self.headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        self.timeout = 30
        self.api_prefix = api_prefix
        self.excluded_repos_list = (
            [] if exclude_repos is None else exclude_repos.strip().split(",")
        )

    def filter_excluded_repos(self, url: str) -> bool:
        """
        True only if the url doesn't contain any string from
        `self.excluded_repos_list`
        """
        return not any(
            (excluded_repo in url for excluded_repo in self.excluded_repos_list)
        )

    def append_response(
        self,
        URLs: list[str],
        resp: dict,
        key: str,
        exclude_forked: bool = False,
        owner: str | None = None,
    ):
        """Append the urls from response from a given criteria"""
        for i, _ in enumerate(resp):
            if exclude_forked and resp[i]["fork"]:
                continue
            if owner is not None and resp[i]["owner"]["login"] != owner:
                continue
            resp_i_key = resp[i][key]
            if self.filter_excluded_repos(resp_i_key):
                URLs.append(resp_i_key)

    def user_gists(
        self,
        user: str,
        username: str | None = None,
        token: str | None = None,
        owner_only: bool = False,
    ):
        """
        Returns a list of GIT URLs for accessible gists.
        Input:-
        user: Github user.
        Optional Input:-
        username: Github username.
        token: Github token or password.
        Output:-
        a list of Github gist repositories URLs.
        """

        urls = []
        resp = []
        current_page = 1
        while len(resp) != 0 or current_page == 1:
            API = f"{self.api_prefix}/users/{user}/gists?page={current_page}"
            if username is None or token is None:
                resp = requests.get(
                    API, headers=self.headers, timeout=self.timeout
                ).text
            else:
                resp = requests.get(
                    API,
                    headers=self.headers,
                    timeout=self.timeout,
                    auth=(username, token),
                ).text
            resp = json.loads(resp)

            owner = username if owner_only else None

            if self.check_response(resp) != 0:
                return []

            self.append_response(urls, resp, "git_pull_url", owner=owner)
            current_page += 1
        return urls

    def authenticated_gists(self, username, token, owner_only=False):
        """
        Returns a list of gists of an authenticated user.
        Input:-
        username: Github username.
        token: Github token or password.
        Output:-
        a list of Github gist repositories URLs.
        """

        urls = []
        resp = []
        current_page = 1
        while len(resp) != 0 or current_page == 1:
            API = "{0}/gists?page={1}".format(self.api_prefix, current_page)
            resp = requests.get(
                API, headers=self.headers, timeout=self.timeout, auth=(username, token)
            ).text
            resp = json.loads(resp)
            owner = username if owner_only else None
            self.append_response(urls, resp, "git_pull_url", owner=owner)
            current_page += 1

        return urls

    def from_user(
        self,
        user,
        username=None,
        token=None,
        include_gists=False,
        exclude_forked=False,
        owner_only=False,
    ):
        """
        Retrieves a list of repositories for a Github user.
        Input:-
        user: Github username.
        Optional Input:-
        username: Github username.
        token: Github token or password.
        Output:-
        a list of Github repositories URLs.
        """

        urls = []
        resp = []
        current_page = 1
        while len(resp) != 0 or current_page == 1:
            api = f"{self.api_prefix}/users/{user}/repos?per_page=40000000&page={current_page}"

            if username is None or token is None:
                resp = requests.get(
                    api, headers=self.headers, timeout=self.timeout
                ).text
            else:
                resp = requests.get(
                    api,
                    headers=self.headers,
                    timeout=self.timeout,
                    auth=(username, token),
                ).text
            resp = json.loads(resp)

            if self.check_response(resp) != 0:
                return []

            owner = username if owner_only else None

            self.append_response(urls, resp, "git_url", exclude_forked, owner=owner)

            if include_gists is True:
                urls.extend(self.user_gists(user, username=username, token=token))
            current_page += 1
        return urls

    def from_org(
        self,
        org_name: str,
        username: str | None = None,
        token: str | None = None,
        exclude_forked: bool = False,
        owner_only: bool = False,
    ) -> list[str]:
        """
        Retrieves a list of repositories for a Github organization.
        Input:-
        org_name: Github organization name.
        Optional Input:-
        username: Github username.
        token: Github token or password.
        Output:-
        a list of Github repositories URLs.
        """

        urls = []
        resp = []
        current_page = 1
        while len(resp) != 0 or current_page == 1:
            API = "{0}/orgs/{1}/repos?per_page=40000000&page={2}".format(
                self.api_prefix, org_name, current_page
            )
            if username is None or token is None:
                resp = requests.get(
                    API, headers=self.headers, timeout=self.timeout
                ).text
            else:
                resp = requests.get(
                    API,
                    headers=self.headers,
                    timeout=self.timeout,
                    auth=(username, token),
                ).text
            resp = json.loads(resp)

            if self.check_response(resp) != 0:
                return []

            owner = username if owner_only else None

            self.append_response(urls, resp, "git_url", exclude_forked, owner)
            current_page += 1
        return urls

    def from_org_include_users(
        self,
        org_name: str,
        username: str | None = None,
        token: str | None = None,
        include_gists: bool = False,
        exclude_forked: bool = False,
    ) -> list[str]:
        """
        Retrieves a list of repositories for a Github organization
        and repositories of the Github organization's members.
        Input:-
        org_name: Github organization name.
        Optional Input:-
        username: Github username.
        token: Github token or password.
        Output:-
        a list of Github repositories URLs.
        """

        members = []
        resp = []
        current_page = 1
        urls = self.from_org(
            org_name, username=username, token=token, exclude_forked=exclude_forked
        )

        while len(resp) != 0 or current_page == 1:
            api = "{0}/orgs/{1}/members?per_page=40000000&page={2}".format(
                self.api_prefix, org_name, current_page
            )
            if username is None or token is None:
                resp = requests.get(
                    api, headers=self.headers, timeout=self.timeout
                ).text
            else:
                resp = requests.get(
                    api,
                    headers=self.headers,
                    timeout=self.timeout,
                    auth=(username, token),
                ).text
            resp = json.loads(resp)

            if self.check_response(resp) != 0:
                return []

            current_page += 1
            for i in range(len(resp)):
                members.append(resp[i]["login"])

        for member in members:
            urls.extend(
                self.from_user(
                    member, username=username, token=token, include_gists=include_gists
                )
            )

        return urls

    def check_authentication(self, username: str, token: str) -> bool:
        """
        Checks whether an authentication credentials are valid or not.
        Input:-
        username: Github username.
        token: Github token or password.
        Output:-
        True: if the authentication credentials are valid.
        False: if the authentication credentials are invalid.
        """

        api = "{0}/user".format(self.api_prefix)
        resp = requests.get(
            api, auth=(username, token), timeout=self.timeout, headers=self.headers
        )
        return resp.status_code == 200

    def check_response(self, response: dict) -> int:
        """
        Validates whether there an error in the response.
        """
        try:
            if "API rate limit exceeded" in response["message"]:
                print("[!] Error: Github API rate limit exceeded")
                return 1
        except TypeError:
            pass

        try:
            if response["message"] == "Not Found":
                return 2  # The organization does not exist
        except TypeError:
            pass

        return 0

    def from_authenticated_user(
        self,
        username: str | None,
        token: str,
        exclude_forked: bool,
        owner_only: bool = False,
    ) -> list[str]:
        """
        Retrieves a list of Github repositories than an authenticated user
        has access to.
        Input:-
        username: Github username.
        token: Github token or password.
        Output:-
        a list of Github repositories URLs.
        """
        if username is None:
            raise ValueError("username can't be None")
        urls = []
        resp = []
        current_page = 1

        while len(resp) != 0 or current_page == 1:
            api = f"{self.api_prefix}/user/repos?per_page=40000000&type=all&page={current_page}"
            resp = requests.get(
                api, headers=self.headers, timeout=self.timeout, auth=(username, token)
            ).text
            resp = json.loads(resp)
            owner = username if owner_only else None

            self.append_response(urls, resp, "git_url", exclude_forked, owner=owner)
            current_page += 1
        return urls


def parse_git_url(url, username: str | None = None, token: str | None = None) -> str:
    """
    This function parses the GIT URL.
    """

    url = url.replace("git://", "https://")
    if (username or token) is not None:
        url = url.replace("https://", "https://{0}:{1}@".format(username, token))
    return url


def get_repopath(repo_username: str, repo_name: str, prefix_mode: str):
    """
    Returns a string of the repo path.
    """
    repopath = ""
    if prefix_mode == "none":
        repopath = repo_name
    elif prefix_mode == "underscore":
        repopath = repo_username + "_" + repo_name
    elif prefix_mode == "directory":
        repopath = repo_username + "/" + repo_name
    else:
        raise ValueError("Unknown prefix_mode %s", prefix_mode)

    repopath = repopath.strip(".git")
    if "@" in repopath:
        repopath = repopath.replace(repopath[: repopath.index("@") + 1], "")
    return repopath


def create_dirs(cloningpath: str, prefix_mode: str, url: str):
    try:
        if not os.path.exists(cloningpath):
            os.mkdir(cloningpath)
        if prefix_mode == "directory":
            repo_username = url.split("/")[-2]
            if not os.path.exists(cloningpath + "/" + repo_username):
                os.mkdir(cloningpath + "/" + repo_username)
    except Exception:
        print("Error: There is an error in creating directories")


def username_name(url: str) -> tuple[str, str]:
    splits = url.split("/")
    return (splits[-2], splits[-1])


def clone_repo(
    url,
    cloningpath: str,
    username: str | None = None,
    token: str | None = None,
    prefix_mode: str = "underscore",
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
        create_dirs(cloningpath, prefix_mode, url)
        url = parse_git_url(url, username=username, token=token)
        repo_username, repo_name = username_name(url)
        repopath = get_repopath(repo_username, repo_name, prefix_mode)

        fullpath = cloningpath + "/" + repopath
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
    task: str,
    cloning_path: str,
    username: str | None,
    token: str | None,
    prefix_mode: str,
) -> threading.Thread:
    return threading.Thread(
        target=clone_repo,
        args=(task, cloning_path),
        kwargs={
            "username": username,
            "token": token,
            "prefix_mode": prefix_mode,
        },
        daemon=True,
    )


def clone_bulk_repos(
    urls: list[str],
    cloning_path: str,
    threads_limit: int = 5,
    username: str | None = None,
    token: str | None = None,
    prefix_mode: str = "underscore",
):
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
    for url in urls:
        q.put(url)

    threads_state: list[threading.Thread] = []
    while not q.empty():
        task = q.get()
        t = build_thread(task, cloning_path, username, token, prefix_mode)
        if threading.active_count() < threads_limit + 1:
            t.start()
            threads_state.append(t)
        else:
            time.sleep(0.5)

    for t in threads_state:
        if t.is_alive:
            t.join()


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


class ConfigError(Exception):
    """Exception for configuration validation errors."""

    pass


@dataclass
class Config:
    users: str | None
    organizations: str | None
    include_organization_members: bool
    output_path: str
    threads_limit: int
    authentication: str | None
    include_authenticated_repos: bool
    include_gists: bool
    echo_urls: bool
    prefix_mode: str
    api_prefix: str
    exclude_repos: str | None
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

    def authenticated_repos(self) -> list[str]:
        if self.config.token is None:
            raise ValueError("token can't be None")

        return GetReposURLs(
            self.config.api_prefix, self.config.exclude_repos
        ).from_authenticated_user(
            self.config.username,
            self.config.token,
            self.config.exclude_forked,
            self.config.owner_only,
        )

    def authenticated_gists(self) -> list[str]:
        return GetReposURLs(
            self.config.api_prefix, self.config.exclude_repos
        ).authenticated_gists(self.config.username, self.config.token)

    def authenticated_user(self, user: str) -> list[str]:
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

    def organization_members(self, organization: str) -> list[str]:
        return GetReposURLs(self.config.api_prefix, self.config.exclude_repos).from_org(
            organization,
            username=self.config.username,
            token=self.config.token,
            exclude_forked=self.config.exclude_forked,
        )

    def org_include_users(self, organization: str) -> list[str]:
        return GetReposURLs(
            self.config.api_prefix, self.config.exclude_repos
        ).from_org_include_users(
            organization,
            username=self.config.username,
            token=self.config.token,
            include_gists=self.config.include_gists,
            exclude_forked=self.config.exclude_forked,
        )

    def sync_urls(self, urls: list[str]) -> None:
        urls = list(set(urls))
        if self.config.echo_urls:
            for url in urls:
                print(
                    parse_git_url(
                        url, username=self.config.username, token=self.config.token
                    )
                )
            return

        clone_bulk_repos(
            urls,
            self.config.output_path,
            threads_limit=self.config.threads_limit,
            username=self.config.username,
            token=self.config.token,
            prefix_mode=self.config.prefix_mode,
        )

    def build_urls(self) -> list[str]:
        urls = []
        if (
            self.config.include_authenticated_repos
            and self.config.username is not None
            and self.config.token is not None
            and self.config.owner_only is not None
        ):
            urls.extend(self.authenticated_repos())
            if self.config.include_gists:
                urls.extend(self.authenticated_gists())

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
        self.sync_urls(urls)


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
