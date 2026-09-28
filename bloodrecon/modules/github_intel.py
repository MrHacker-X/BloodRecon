#!/usr/bin/env python3
"""
GitHub Intelligence Module
Gather intelligence on GitHub users and repositories
Author : Alex Butler (@MrHacker-X)
Org    : Vritra Security Organization
"""

import os
import requests
from datetime import datetime
from bloodrecon.modules.colors import Fore, Style

def _github_headers():
    """Build GitHub API headers, using GITHUB_TOKEN when available.

    Unauthenticated GitHub API is limited to 60 requests/hour per IP and is
    often blocked entirely on shared/CI infrastructure; a token raises the
    limit to 5,000/hour.
    """
    headers = {'User-Agent': 'BloodRecon-OSINT/1.0', 'Accept': 'application/vnd.github+json'}
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = f'Bearer {token}'
    return headers


def _handle_rate_limit(response):
    """Print a helpful message when the GitHub API rate limit is hit."""
    if response.status_code == 403 and response.headers.get('X-RateLimit-Remaining') == '0':
        reset = response.headers.get('X-RateLimit-Reset')
        when = ''
        if reset and reset.isdigit():
            from datetime import datetime as _dt
            when = " — resets " + _dt.fromtimestamp(int(reset)).strftime('%H:%M:%S')
        print(f"    {Fore.RED}✗ GitHub API rate limit exceeded{when}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Tip: export GITHUB_TOKEN=... to raise the limit to 5,000 req/h{Style.RESET_ALL}")
        return True
    return False


def analyze_github_target(target):
    """Analyze GitHub user or repository"""
    try:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {Fore.YELLOW}GITHUB INTELLIGENCE{Fore.CYAN}                       ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Determine if target is user or repo
        if '/' in target:
            analyze_repository(target)
        else:
            analyze_user(target)
            
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error in GitHub analysis: {str(e)}{Style.RESET_ALL}")

def analyze_user(username):
    """Analyze GitHub user profile"""
    try:
        print(f"\n{Fore.GREEN}[+] Analyzing GitHub User: {Fore.YELLOW}{username}{Style.RESET_ALL}")
        
        # Get user information
        user_url = f"https://api.github.com/users/{username}"
        headers = _github_headers()
        
        try:
            response = requests.get(user_url, headers=headers, timeout=10)
            if response.status_code == 200:
                user_data = response.json()
                display_user_info(user_data)
                
                # Get repositories
                get_user_repositories(username, headers)
                
                # Get user events (recent activity)
                get_user_activity(username, headers)
                
            elif response.status_code == 404:
                print(f"    {Fore.RED}✗ User not found{Style.RESET_ALL}")
            elif _handle_rate_limit(response):
                pass
            else:
                print(f"    {Fore.YELLOW}⚠ API returned status code: {response.status_code}{Style.RESET_ALL}")
                
        except requests.RequestException as e:
            print(f"    {Fore.RED}✗ Request failed: {str(e)}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Error analyzing user: {str(e)}{Style.RESET_ALL}")

def analyze_repository(repo_path):
    """Analyze GitHub repository"""
    try:
        print(f"\n{Fore.GREEN}[+] Analyzing Repository: {Fore.YELLOW}{repo_path}{Style.RESET_ALL}")
        
        repo_url = f"https://api.github.com/repos/{repo_path}"
        headers = _github_headers()
        
        try:
            response = requests.get(repo_url, headers=headers, timeout=10)
            if response.status_code == 200:
                repo_data = response.json()
                display_repo_info(repo_data)
                
                # Get contributors
                get_repo_contributors(repo_path, headers)
                
                # Get recent commits
                get_recent_commits(repo_path, headers)
                
            elif response.status_code == 404:
                print(f"    {Fore.RED}✗ Repository not found{Style.RESET_ALL}")
            elif _handle_rate_limit(response):
                pass
            else:
                print(f"    {Fore.YELLOW}⚠ API returned status code: {response.status_code}{Style.RESET_ALL}")
                
        except requests.RequestException as e:
            print(f"    {Fore.RED}✗ Request failed: {str(e)}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Error analyzing repository: {str(e)}{Style.RESET_ALL}")

def display_user_info(user_data):
    """Display user information"""
    print(f"\n{Fore.GREEN}[+] User Profile:{Style.RESET_ALL}")
    print(f"    Username: {Fore.CYAN}{user_data.get('login', 'N/A')}{Style.RESET_ALL}")
    print(f"    Name: {Fore.CYAN}{user_data.get('name', 'Not provided')}{Style.RESET_ALL}")
    print(f"    Bio: {Fore.CYAN}{user_data.get('bio', 'No bio')}{Style.RESET_ALL}")
    print(f"    Location: {Fore.CYAN}{user_data.get('location', 'Not specified')}{Style.RESET_ALL}")
    print(f"    Company: {Fore.CYAN}{user_data.get('company', 'Not specified')}{Style.RESET_ALL}")
    print(f"    Blog: {Fore.CYAN}{user_data.get('blog', 'None')}{Style.RESET_ALL}")
    print(f"    Email: {Fore.CYAN}{user_data.get('email', 'Not public')}{Style.RESET_ALL}")
    print(f"    Twitter: {Fore.CYAN}{user_data.get('twitter_username', 'Not linked')}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Account Statistics:{Style.RESET_ALL}")
    print(f"    Public Repos: {Fore.YELLOW}{user_data.get('public_repos', 0)}{Style.RESET_ALL}")
    print(f"    Public Gists: {Fore.YELLOW}{user_data.get('public_gists', 0)}{Style.RESET_ALL}")
    print(f"    Followers: {Fore.YELLOW}{user_data.get('followers', 0)}{Style.RESET_ALL}")
    print(f"    Following: {Fore.YELLOW}{user_data.get('following', 0)}{Style.RESET_ALL}")
    
    if user_data.get('created_at'):
        created_date = datetime.strptime(user_data['created_at'], '%Y-%m-%dT%H:%M:%SZ')
        print(f"    Account Created: {Fore.YELLOW}{created_date.strftime('%Y-%m-%d')}{Style.RESET_ALL}")
    
    if user_data.get('updated_at'):
        updated_date = datetime.strptime(user_data['updated_at'], '%Y-%m-%dT%H:%M:%SZ')
        print(f"    Last Updated: {Fore.YELLOW}{updated_date.strftime('%Y-%m-%d')}{Style.RESET_ALL}")

def display_repo_info(repo_data):
    """Display repository information"""
    print(f"\n{Fore.GREEN}[+] Repository Details:{Style.RESET_ALL}")
    print(f"    Name: {Fore.CYAN}{repo_data.get('name', 'N/A')}{Style.RESET_ALL}")
    print(f"    Full Name: {Fore.CYAN}{repo_data.get('full_name', 'N/A')}{Style.RESET_ALL}")
    print(f"    Description: {Fore.CYAN}{repo_data.get('description', 'No description')}{Style.RESET_ALL}")
    print(f"    Language: {Fore.CYAN}{repo_data.get('language', 'Not specified')}{Style.RESET_ALL}")
    print(f"    Private: {Fore.CYAN}{repo_data.get('private', False)}{Style.RESET_ALL}")
    print(f"    Fork: {Fore.CYAN}{repo_data.get('fork', False)}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[+] Repository Statistics:{Style.RESET_ALL}")
    print(f"    Stars: {Fore.YELLOW}{repo_data.get('stargazers_count', 0)}{Style.RESET_ALL}")
    print(f"    Watchers: {Fore.YELLOW}{repo_data.get('watchers_count', 0)}{Style.RESET_ALL}")
    print(f"    Forks: {Fore.YELLOW}{repo_data.get('forks_count', 0)}{Style.RESET_ALL}")
    print(f"    Issues: {Fore.YELLOW}{repo_data.get('open_issues_count', 0)}{Style.RESET_ALL}")
    print(f"    Size: {Fore.YELLOW}{repo_data.get('size', 0)} KB{Style.RESET_ALL}")
    
    if repo_data.get('created_at'):
        created_date = datetime.strptime(repo_data['created_at'], '%Y-%m-%dT%H:%M:%SZ')
        print(f"    Created: {Fore.YELLOW}{created_date.strftime('%Y-%m-%d')}{Style.RESET_ALL}")
    
    if repo_data.get('pushed_at'):
        pushed_date = datetime.strptime(repo_data['pushed_at'], '%Y-%m-%dT%H:%M:%SZ')
        print(f"    Last Push: {Fore.YELLOW}{pushed_date.strftime('%Y-%m-%d')}{Style.RESET_ALL}")

def get_user_repositories(username, headers):
    """Get user's public repositories"""
    try:
        repos_url = f"https://api.github.com/users/{username}/repos?sort=updated&per_page=10"
        response = requests.get(repos_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            repos = response.json()
            if repos:
                print(f"\n{Fore.GREEN}[+] Recent Repositories:{Style.RESET_ALL}")
                for repo in repos[:5]:  # Show top 5
                    print(f"    • {Fore.CYAN}{repo['name']}{Style.RESET_ALL} - {Fore.YELLOW}⭐{repo['stargazers_count']}{Style.RESET_ALL}")
                    if repo.get('description'):
                        print(f"      {Fore.WHITE}{repo['description'][:80]}{'...' if len(repo.get('description', '')) > 80 else ''}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}[!] No public repositories found{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to get repositories: {str(e)}{Style.RESET_ALL}")

def get_user_activity(username, headers):
    """Get user's recent activity"""
    try:
        events_url = f"https://api.github.com/users/{username}/events/public?per_page=5"
        response = requests.get(events_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            events = response.json()
            if events:
                print(f"\n{Fore.GREEN}[+] Recent Activity:{Style.RESET_ALL}")
                for event in events[:3]:  # Show top 3
                    event_type = event.get('type', 'Unknown')
                    repo_name = event.get('repo', {}).get('name', 'Unknown')
                    created_at = event.get('created_at', '')
                    
                    if created_at:
                        date = datetime.strptime(created_at, '%Y-%m-%dT%H:%M:%SZ')
                        date_str = date.strftime('%Y-%m-%d %H:%M')
                    else:
                        date_str = 'Unknown'
                    
                    print(f"    • {Fore.CYAN}{event_type}{Style.RESET_ALL} on {Fore.YELLOW}{repo_name}{Style.RESET_ALL} - {Fore.WHITE}{date_str}{Style.RESET_ALL}")
                    
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to get user activity: {str(e)}{Style.RESET_ALL}")

def get_repo_contributors(repo_path, headers):
    """Get repository contributors"""
    try:
        contributors_url = f"https://api.github.com/repos/{repo_path}/contributors?per_page=5"
        response = requests.get(contributors_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            contributors = response.json()
            if contributors:
                print(f"\n{Fore.GREEN}[+] Top Contributors:{Style.RESET_ALL}")
                for contributor in contributors[:5]:
                    username = contributor.get('login', 'Unknown')
                    contributions = contributor.get('contributions', 0)
                    print(f"    • {Fore.CYAN}{username}{Style.RESET_ALL} - {Fore.YELLOW}{contributions} contributions{Style.RESET_ALL}")
                    
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to get contributors: {str(e)}{Style.RESET_ALL}")

def get_recent_commits(repo_path, headers):
    """Get recent commits"""
    try:
        commits_url = f"https://api.github.com/repos/{repo_path}/commits?per_page=3"
        response = requests.get(commits_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            commits = response.json()
            if commits:
                print(f"\n{Fore.GREEN}[+] Recent Commits:{Style.RESET_ALL}")
                for commit in commits:
                    message = commit.get('commit', {}).get('message', 'No message')
                    author = commit.get('commit', {}).get('author', {}).get('name', 'Unknown')
                    date = commit.get('commit', {}).get('author', {}).get('date', '')
                    
                    if date:
                        commit_date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%SZ')
                        date_str = commit_date.strftime('%Y-%m-%d %H:%M')
                    else:
                        date_str = 'Unknown'
                    
                    print(f"    • {Fore.CYAN}{message[:60]}{'...' if len(message) > 60 else ''}{Style.RESET_ALL}")
                    print(f"      by {Fore.YELLOW}{author}{Style.RESET_ALL} on {Fore.WHITE}{date_str}{Style.RESET_ALL}")
                    
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to get commits: {str(e)}{Style.RESET_ALL}")
