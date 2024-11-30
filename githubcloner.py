#!/usr/bin/env python3

import json
import os
import queue
import threading
import time
import argparse

from dataclasses import dataclass
from sys import exit

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
        self, username: str, token: str, exclude_forked: bool, owner_only: bool = False
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
    return repopath


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
        try:
            if not os.path.exists(cloningpath):
                os.mkdir(cloningpath)
            if prefix_mode == "directory":
                repo_username = url.split("/")[-2]
                if not os.path.exists(cloningpath + "/" + repo_username):
                    os.mkdir(cloningpath + "/" + repo_username)
        except Exception:
            print("Error: There is an error in creating directories")

        url = parse_git_url(url, username=username, token=token)

        repo_username = url.split("/")[-2]
        repo_name = url.split("/")[-1]

        repopath = get_repopath(repo_username, repo_name, prefix_mode)

        if repopath.endswith(".git"):
            repopath = repopath[:-4]

        if "@" in repopath:
            repopath = repopath.replace(repopath[: repopath.index("@") + 1], "")

        fullpath = cloningpath + "/" + repopath
        with threading.Lock():
            print(fullpath)

        if os.path.exists(fullpath):
            git.Repo(fullpath).remote().pull()
        else:
            git.Repo.clone_from(url, fullpath)
    except Exception as e:
        print(e)
        print("Error: There was an error in cloning [{}]".format(url))


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
    threads_state: list[threading.Thread] = []
    for url in urls:
        q.put(url)
    while not q.empty():
        t = threading.Thread(
            target=clone_repo,
            args=(
                q.get(),
                cloning_path,
            ),
            kwargs={
                "username": username,
                "token": token,
                "prefix_mode": prefix_mode,
            },
        )
        t.daemon = True
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
    Parses the user inputed arguments from stdin and returns a NameSpace.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--user",
        dest="users",
        help="Github user (comma-separated input for multiple Github users).",
        action="store",
    )
    parser.add_argument(
        "-org",
        "--org",
        dest="organizations",
        help="Github organization"
        + "(comma-separated input for multiple Github organizations).",
        action="store",
    )
    parser.add_argument(
        "--include-org-members",
        dest="include_organization_members",
        help="Include the members of a Github organization.",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--output-path",
        dest="output_path",
        help="The directory to use in cloning Git repositories.",
        action="store",
    )
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads_limit",
        help="Threads used in cloning repositories (Default: 5).",
        action="store",
        default=5,
    )
    parser.add_argument(
        "-a",
        "--authentication",
        dest="authentication",
        help="Github authentication credentials (username:token).",
        action="store",
    )
    parser.add_argument(
        "--include-authenticated-repos",
        dest="include_authenticated_repos",
        help="Include repositories that the authenticated Github"
        + " account have access to.",
        action="store_true",
    )
    parser.add_argument(
        "--include-gists",
        dest="include_gists",
        help="Include gists.",
        action="store_true",
    )
    parser.add_argument(
        "--echo-urls",
        dest="echo_urls",
        help="Print gathered URLs only and then exit.",
        action="store_true",
    )
    parser.add_argument(
        "--prefix-mode",
        dest="prefix_mode",
        help="Sets the prefix mode for the repo directory. "
        "underscore: /Netflix_repo-name, directory:"
        " /Netflix/repo-name, none: /repo-name",
        action="store",
        default="underscore",
    )
    parser.add_argument(
        "--api-prefix",
        dest="api_prefix",
        help="Github Enterprise domain to prefix to API calls",
        action="store",
        default="https://api.github.com",
    )
    parser.add_argument(
        "--exclude_repos",
        dest="exclude_repos",
        help="Exclude a list of comma separated repos: 'repo1,repo2,...'",
        action="store",
    )
    parser.add_argument(
        "--exclude_forked",
        dest="exclude_forked",
        help="Exclude forked repositories",
        action="store_true",
    )
    parser.add_argument(
        "--owner_only",
        dest="owner_only",
        help="Exclude repositories you don't own",
        action="store_true",
    )
    return parser.parse_args()


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
    owner_only: bool | None

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
        owner_only = args.owner_only if args.owner_only else None
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
        )

    def validate(self) -> "Config":
        if self.threads_limit > 10:
            print(
                "Error: Using more than 10 threads may cause errors."
                "\nDecrease the amount of used threads."
            )
            print("\nExiting....")
            exit(1)

        if (not self.output_path) and (not self.echo_urls):
            print("Error: The output path is not specified.")
            print("\nExiting...")
            exit(1)

        if not (self.users or self.organizations):
            print(
                "Error: Both Github users and Github organizations are not specified."
            )
            print("\nExiting...")
            exit(1)

        if not str(self.threads_limit).isdigit():
            print("Error: Specified threads specified is invalid.")
            print("\nExiting...")
            exit(1)

        if not self.echo_urls:
            try:
                if not os.path.exists(self.output_path):
                    os.mkdir(self.output_path)
            except Exception as error:
                print("Error: There is an error creating output directory.")
                print(repr(error))
                exit(1)

        if self.authentication is not None:
            if ":" not in self.authentication:
                print(
                    "[!] Error: Incorrect authentication value, must be:"
                    " <username>:<password_or_personal_access_token>"
                )
                print("\nExiting...")
                exit(1)
            if not GetReposURLs(
                self.api_prefix, self.exclude_repos
            ).check_authentication(
                self.authentication.split(":")[0], self.authentication.split(":")[1]
            ):
                print("Error: authentication failed.")
                print("\nExiting...")
                exit(1)
            else:
                self.username = self.authentication.split(":")[0]
                self.token = self.authentication.split(":")[1]
        else:
            self.username = None
            self.token = None

        if (self.include_authenticated_repos is True) and (self.authentication is None):
            print(
                "Error: --include-authenticated-repos is used and --authentication is not provided."
            )
            print("\nExiting...")
            exit(1)

        if self.prefix_mode not in ["none", "underscore", "directory"]:
            print(
                'Error: prefix_mode must be one of: "none", "underscore", "directory".'
            )
            print("\nExiting...")
            exit(1)

        return self


def main():
    """
    The main function.
    """

    args = parse_args()
    config = Config.from_args(args).validate()

    urls = []

    if (
        config.include_authenticated_repos
        and config.username is not None
        and config.token is not None
        and config.owner_only is not None
    ):
        urls.extend(
            GetReposURLs(
                config.api_prefix, config.exclude_repos
            ).from_authenticated_user(
                config.username, config.token, args.exclude_forked, config.owner_only
            )
        )
        if config.include_gists:
            urls.extend(
                GetReposURLs(
                    config.api_prefix, config.exclude_repos
                ).authenticated_gists(config.username, config.token)
            )

    if config.users is not None and config.owner_only is not None:
        users = config.users.replace(" ", "").split(",")
        for user in users:
            urls.extend(
                GetReposURLs(config.api_prefix, config.exclude_repos).from_user(
                    user,
                    username=config.username,
                    token=config.token,
                    include_gists=config.include_gists,
                    exclude_forked=args.exclude_forked,
                    owner_only=config.owner_only,
                )
            )

    if config.organizations is not None:
        organizations = config.organizations.replace(" ", "").split(",")

        for organization in organizations:
            if config.include_organization_members is False:
                urls.extend(
                    GetReposURLs(config.api_prefix, config.exclude_repos).from_org(
                        organization,
                        username=config.username,
                        token=config.token,
                        exclude_forked=args.exclude_forked,
                    )
                )
            else:
                urls.extend(
                    GetReposURLs(
                        config.api_prefix, config.exclude_repos
                    ).from_org_include_users(
                        organization,
                        username=config.username,
                        token=config.token,
                        include_gists=config.include_gists,
                        exclude_forked=args.exclude_forked,
                    )
                )

    urls = list(set(urls))
    if config.echo_urls is True:
        for URL in urls:
            print(parse_git_url(URL, username=config.username, token=config.token))
        return

    clone_bulk_repos(
        urls,
        config.output_path,
        threads_limit=config.threads_limit,
        username=config.username,
        token=config.token,
        prefix_mode=config.prefix_mode,
    )


if __name__ == "__main__":
    main()
