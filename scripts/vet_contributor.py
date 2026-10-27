"""First pass contributor vetting helper, using public GitHub data only.

Usage:
    python3 scripts/vet_contributor.py <github_username>

What it does:
    Fetches the public profile, public repos sorted by update time,
    and public issue and pull request search results for the user,
    plus a separate search for morluto/rea, the official REA repo.
    Prints evidence links, not a final verdict.

What it does not do:
    It does not prove private work, deleted work, or work under another
    username. It does not approve a contributor. A human maintainer must
    read the actual pull requests and commits, and fill in
    docs/CONTRIBUTOR_VETTING_CHECKLIST.md, before any form is sent.
    Stars and forks alone are not contributions.

No token is required for public data, but GitHub rate limits unauthenticated
requests. Set GITHUB_TOKEN in the environment if you hit a rate limit.
The token is never printed, and never committed.
"""
import json
import os
import sys
import urllib.request
import urllib.parse


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "BankShield-HumanGate-Vetting", "Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"_error": str(e), "_url": url}


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/vet_contributor.py <github_username>")
        return 2
    username = sys.argv[1].strip()
    if not username or "/" in username or " " in username:
        print("Give one exact GitHub username, with no spaces and no slash.")
        return 2
    print(f"Vetting first pass for: {username}")
    print(f"Profile: https://github.com/{username}")
    profile = get(f"https://api.github.com/users/{username}")
    if "_error" in profile:
        print("Profile fetch failed:", profile["_error"])
        return 1
    print("Name:", profile.get("name"))
    print("Public repos:", profile.get("public_repos"))
    print("Followers:", profile.get("followers"), "Following:", profile.get("following"))
    print("Created:", profile.get("created_at"), "Updated:", profile.get("updated_at"))
    print("Bio:", profile.get("bio"))
    print("\nMost recently updated public repos:")
    repos = get(f"https://api.github.com/users/{username}/repos?per_page=20&sort=updated")
    if isinstance(repos, list):
        for repo in repos[:10]:
            print(f"  {repo.get('full_name')} updated {repo.get('updated_at')} language {repo.get('language')} stars {repo.get('stargazers_count')} fork {repo.get('fork')}")
    else:
        print("  Repo fetch failed:", repos)
    print("\nPublic issues and pull requests authored by this user, recent first:")
    q = urllib.parse.quote(f"author:{username} type:issue")
    issues = get(f"https://api.github.com/search/issues?q={q}&per_page=10&sort=created&order=desc")
    if isinstance(issues, dict) and "items" in issues:
        print("  Total found in search:", issues.get("total_count"))
        for item in issues["items"][:10]:
            print(f"  {item.get('html_url')} {item.get('title')} state {item.get('state')} repo {item.get('repository_url', '').split('/')[-2:]}")
    else:
        print("  Issue search failed:", issues)
    print("\nREA check, official repo morluto/rea only:")
    q_rea = urllib.parse.quote(f"author:{username} repo:morluto/rea type:issue")
    rea = get(f"https://api.github.com/search/issues?q={q_rea}&per_page=10&sort=created&order=desc")
    if isinstance(rea, dict) and "items" in rea:
        print("  Total found in morluto/rea search:", rea.get("total_count"))
        if rea.get("total_count") == 0:
            print("  REA_NOT_FOUND in this public search. Record that exactly, not as never contributed anywhere.")
        for item in rea["items"][:10]:
            print(f"  {item.get('html_url')} {item.get('title')} state {item.get('state')}")
    else:
        print("  REA search failed:", rea)
    print("\nNext step for a human maintainer:")
    print("  Read the actual merged pull requests above, fill in docs/CONTRIBUTOR_VETTING_CHECKLIST.md,")
    print("  and only then, after vetting, send the form from docs/CONTRIBUTOR_FORM.md when the maintainer provides it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
