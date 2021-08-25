#!/usr/bin/env python3

"""
GitLab to GitHub Migration Script

Assumptions:
* working directory contains settings.json file and extract of project
* git repo already mirrored to GitHub
* master branch never rebased
* no issues or merge requests have been deleted
* no labels or milestones
* no images in comments
* can only recreate open merge requests if fork exists
* only master branch exists
"""

import json
import tempfile
import sys
import os
import requests
import time

SETTINGS_FILE = "settings.json"
MERGE_REQUESTS_FILE = "tree/project/merge_requests.ndjson"
ISSUES_FILE = "tree/project/issues.ndjson"
REQUEST_HEADERS = {
    "Accept": "application/vnd.github.v3+json"
}
RATE_LIMIT_SECONDS = 1

def run_cmd(cmd):
    rc = os.system(cmd)
    if rc != 0:
        raise Exception("(Code: {}) Failed to run command '{}'".format(rc, cmd))

def map_id_display_name(settings):
    usermap = {}
    for k, v in settings["gitlab"]["usermap"].items():
        if isinstance(v, dict) and "name" in v:
            usermap[int(k)] = v["name"]
    return usermap
    
def map_id_username(settings):
    usermap = {}
    for k, v in settings["gitlab"]["usermap"].items():
        if isinstance(v, dict) and "username" in v:
            usermap[int(k)] = v["username"]
    return usermap

def write_git_diff_file(diffs, file):
    changes = False

    with open(file, "w") as f:
        for diff in diffs:
            if diff["utf8_diff"] != "":
                changes = True
                f.write("diff --git a/{0} b/{0}\n".format(diff["new_path"]))
                if diff["deleted_file"]:
                    f.write("deleted file mode {}\n".format(diff["a_mode"]))
                    f.write("--- a/{}\n".format(diff["new_path"]))
                    f.write("+++ /dev/null\n")
                elif diff["new_file"]:
                    f.write("new file mode {}\n".format(diff["b_mode"]))
                    f.write("--- /dev/null\n")
                    f.write("+++ b/{}\n".format(diff["new_path"]))
                else:
                    f.write("--- a/{}\n".format(diff["new_path"]))
                    f.write("+++ b/{}\n".format(diff["new_path"]))
                f.write(diff["utf8_diff"])

    return changes

def create_commit_message(commits):
    return "\n".join([c["message"] for c in commits])

def add_diffs(tmpdir, diffs, commits):
    repo_dir = "{}/repo".format(tmpdir)
    patch_file = "{}/patch".format(tmpdir)
    git_cmd = "git --git-dir='{0}/.git' --work-tree='{0}'".format(repo_dir)
    git_apply = "git apply --unsafe-paths --directory='{}' '{}'".format(repo_dir, patch_file)
    git_add = git_cmd + " add --all"
    git_commit = git_cmd + " commit -q --author=\"{} <{}>\" --date=\"{}\" -m \"{}\"".format(
        commits[0]["author_name"],
        commits[0]["author_email"],
        commits[0]["authored_date"],
        create_commit_message(commits).replace("\"", "\\\"")
    )

    for diff in diffs:
        if diff["renamed_file"]:
            new_dir = os.path.dirname(diff["new_path"])
            if new_dir != "":
                os.makedirs("{}/{}".format(repo_dir, new_dir), exist_ok=True)
            os.rename("{}/{}".format(repo_dir, diff["old_path"]), "{}/{}".format(repo_dir, diff["new_path"]))

    if write_git_diff_file(diffs, patch_file):
        run_cmd(git_apply)
    os.remove(patch_file)

    run_cmd(git_add)
    run_cmd(git_commit)

def post_request(path, body, settings):
    url = "{}/repos/{}/{}".format(settings["github"]["api_url"], settings["github"]["repo"], path)
    r = requests.post(
        url, 
        headers=REQUEST_HEADERS,
        auth=(settings["github"]["username"], settings["github"]["token"]),
        json=body)

    if r.status_code != 201:
        raise Exception("(Code: {}) POST request failed '{}'".format(r.status_code, url))
    
    return r

def patch_request(path, body, settings):
    url = "{}/repos/{}/{}".format(settings["github"]["api_url"], settings["github"]["repo"], path)
    r = requests.patch(
        url, 
        headers=REQUEST_HEADERS,
        auth=(settings["github"]["username"], settings["github"]["token"]),
        json=body)

    if r.status_code != 200:
        raise Exception("(Code: {}) PATCH request failed '{}'".format(r.status_code, url))
    
    return r

def put_request(path, body, settings):
    url = "{}/repos/{}/{}".format(settings["github"]["api_url"], settings["github"]["repo"], path)
    r = requests.put(
        url, 
        headers=REQUEST_HEADERS,
        auth=(settings["github"]["username"], settings["github"]["token"]),
        json=body)

    if r.status_code != 200:
        raise Exception("(Code: {}) PUT request failed '{}'".format(r.status_code, url))
    
    return r

def create_note(user, time, note):
    return "In GitLab, by {} on {}\n\n{}".format(user, time.split("T", 1)[0], note)

def add_notes(notes, n, user_map, settings):
    for note in sorted(notes, key=lambda x: x["id"]):
        if note["system"]:
            continue

        text = note["note"]
        if note["position"]:
            text = "<em>{} line {}</em>\n\n{}".format(
                note["position"]["new_path"],
                note["position"]["new_line"],
                note["note"])

        post_request("issues/{}/comments".format(n), {"body": create_note(user_map[note["author_id"]], note["created_at"], text)}, settings)
        time.sleep(RATE_LIMIT_SECONDS)

def object_created_in_github(iid, file):
    with open(file, "a") as f:
        f.write("{}\n".format(iid))

def get_objects_created(file):
    if os.path.isfile(file):
        with open(file, "r") as f:
            lines = f.readlines()
        return [int(l.strip()) for l in lines]
    else:
        return []

def add_pull(mr, target, source, name_map, username_map, settings):
    print("Creating pull request '{} <- {}'".format(target, source))

    mr_body = {
        "title": mr["title"],
        "body": create_note(name_map[mr["author_id"]], mr["created_at"], mr["description"]),
        "base": target,
        "head": source
    }
    r = post_request("pulls", mr_body, settings)
    object_created_in_github(mr["iid"], "merge_requests_added")
    time.sleep(RATE_LIMIT_SECONDS)
    pr = r.json()["number"]

    if mr["assignee_id"] and mr["state"] == "opened" and mr["assignee_id"] in username_map:
        try:
            patch_request("issues/{}".format(pr), {"assignees": [username_map[mr["assignee_id"]]]}, settings)
        except:
            print("Failed to assign {} to #{}, ignoring...".format(username_map[mr["assignee_id"]], pr))
        time.sleep(RATE_LIMIT_SECONDS)

    add_notes(mr["notes"], pr, name_map, settings)

    if mr["state"] == "merged":
        put_request("pulls/{}/merge".format(pr), {}, settings)
        time.sleep(RATE_LIMIT_SECONDS)
    elif mr["state"] == "closed":
        patch_request("pulls/{}".format(pr), {"state": "closed"}, settings)
        time.sleep(RATE_LIMIT_SECONDS)

def migrate_merge_requests(merge_requests, settings):
    already_done = get_objects_created("merge_requests_added")
    name_map = map_id_display_name(settings)
    username_map = map_id_username(settings)

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = "{}/repo".format(tmpdir)
        os.system("git clone -q '{}' '{}'".format(settings["github"]["clone"], repo_dir))
        git_cmd = "git --git-dir='{0}/.git' --work-tree='{0}'".format(repo_dir)
        run_cmd(git_cmd + " config user.name '{}'".format(settings["github"]["username"]))
        run_cmd(git_cmd + " config user.email '{}'".format(settings["github"]["email"]))
        git_checkout = git_cmd + " checkout -q '{}'"
        git_branch = git_cmd + " checkout -q -b '{}'"
        git_push = git_cmd + " push -q --set-upstream origin '{}' > /dev/null 2> /dev/null"
        git_delete_remote_branch = git_cmd + " push -q --delete origin '{}'"
        git_delete_local_branch = git_cmd + " branch -q -D '{}'"
        git_fetch_mr = git_cmd + " fetch -q origin merge-requests/{}/head:{}"

        for mr in sorted(merge_requests, key=lambda x: x["iid"]):
            if mr["iid"] in already_done:
                continue
            
            if mr["state"] == "closed":
                if not mr["merge_request_diff"]["merge_request_diff_files"] or not mr["merge_request_diff"]["merge_request_diff_commits"]:
                    continue

            print("Processing merge request '{}'".format(mr["title"]))

            if mr["state"] == "merged" or mr["state"] == "closed":
                if mr["state"] == "merged":
                    target_branch = "{}-{}".format(mr["target_branch"], mr["merge_request_diff"]["base_commit_sha"][:7])
                    source_branch = mr["source_branch"]

                    # Create target branch
                    run_cmd(git_checkout.format(mr["target_branch"]))
                    run_cmd(git_checkout.format(mr["merge_request_diff"]["base_commit_sha"]))
                    run_cmd(git_branch.format(target_branch))
                    run_cmd(git_push.format(target_branch))

                    # Create source branch
                    run_cmd(git_checkout.format(mr["target_branch"]))
                    run_cmd(git_checkout.format(mr["merge_request_diff"]["head_commit_sha"]))
                    run_cmd(git_branch.format(source_branch))
                    run_cmd(git_push.format(source_branch))
                elif mr["state"] == "closed":
                    target_branch = mr["target_branch"]
                    source_branch = mr["source_branch"]

                    # Create source branch
                    run_cmd(git_checkout.format(mr["target_branch"]))
                    run_cmd(git_checkout.format(mr["merge_request_diff"]["base_commit_sha"]))
                    run_cmd(git_branch.format(source_branch))
                    add_diffs(tmpdir, mr["merge_request_diff"]["merge_request_diff_files"], mr["merge_request_diff"]["merge_request_diff_commits"])
                    run_cmd(git_push.format(source_branch))
                
                run_cmd(git_checkout.format(mr["target_branch"]))

                add_pull(mr, target_branch, source_branch, name_map, username_map, settings)
                
                run_cmd(git_delete_remote_branch.format(source_branch))
                run_cmd(git_delete_local_branch.format(source_branch))
                if mr["state"] == "merged":
                    run_cmd(git_delete_remote_branch.format(target_branch))
                    run_cmd(git_delete_local_branch.format(target_branch))
            elif mr["state"] == "opened":
                target_branch = mr["target_branch"]
                source_branch = "{}:{}".format(username_map[mr["author_id"]], mr["source_branch"])
                add_pull(mr, target_branch, source_branch, name_map, username_map, settings)

def migrate_issues(issues, settings):
    already_done = get_objects_created("issues_added")
    name_map = map_id_display_name(settings)
    username_map = map_id_username(settings)

    for issue in sorted(issues, key=lambda x: x["iid"]):
        if issue["iid"] in already_done:
            continue
        
        print("Adding issue '{}'".format(issue["title"]))

        issue_body = {
            "title": issue["title"],
            "body": create_note(name_map[issue["author_id"]], issue["created_at"], issue["description"])#,
            # "labels": [l["label"]["title"] for l in issue["label_links"]]
        }
        r = post_request("issues", issue_body, settings)
        object_created_in_github(issue["iid"], "issues_added")
        time.sleep(RATE_LIMIT_SECONDS)
        n = r.json()["number"]
        
        assignees = [
            username_map[a["user_id"]]
            for a in issue["issue_assignees"]
            if a["user_id"] in username_map
        ]
        if not issue["closed_at"] and assignees:
            try:
                patch_request("issues/{}".format(n), {"assignees": assignees}, settings)
            except:
                print("Failed to set assignees for #{}, ignoring...".format(n))
            time.sleep(RATE_LIMIT_SECONDS)

        add_notes(issue["notes"], n, name_map, settings)

        if issue["closed_at"]:
            patch_request("issues/{}".format(n), {"state": "closed"}, settings)
            time.sleep(RATE_LIMIT_SECONDS)
        
def main():
    with open(SETTINGS_FILE, "r") as settings_file:
        settings = json.load(settings_file)
    
    if ("github" not in settings
            or not isinstance(settings["github"], dict)):
        print("Error: github section not found in settings", file=sys.stderr)
        sys.exit(1)

    if ("gitlab" not in settings
            or not isinstance(settings["gitlab"], dict)):
        print("Error: gitlab section not found in settings", file=sys.stderr)
        sys.exit(1)

    if ("clone" not in settings["github"]
            or not isinstance(settings["github"]["clone"], str)
            or settings["github"]["clone"] == ""):
        print("Error: please configure github clone", file=sys.stderr)
        sys.exit(1)

    if ("api_url" not in settings["github"]
            or not isinstance(settings["github"]["api_url"], str)
            or settings["github"]["api_url"] == ""):
        print("Error: please configure github api_url", file=sys.stderr)
        sys.exit(1)

    if ("repo" not in settings["github"]
            or not isinstance(settings["github"]["repo"], str)
            or settings["github"]["repo"] == ""):
        print("Error: please configure github repo", file=sys.stderr)
        sys.exit(1)

    if ("username" not in settings["github"]
            or not isinstance(settings["github"]["username"], str)
            or settings["github"]["username"] == ""):
        print("Error: please configure github username", file=sys.stderr)
        sys.exit(1)

    if ("email" not in settings["github"]
            or not isinstance(settings["github"]["email"], str)
            or settings["github"]["email"] == ""):
        print("Error: please configure github email", file=sys.stderr)
        sys.exit(1)

    if ("token" not in settings["github"]
            or not isinstance(settings["github"]["token"], str)
            or settings["github"]["token"] == ""):
        print("Error: please configure github token", file=sys.stderr)
        sys.exit(1)

    if ("usermap" not in settings["gitlab"]
            or not isinstance(settings["gitlab"]["usermap"], dict)
            or settings["gitlab"]["usermap"] == {}):
        print("Error: please configure gitlab usermap", file=sys.stderr)
        sys.exit(1)

    with open(MERGE_REQUESTS_FILE, "r") as merge_requests_file:
        merge_requests = [json.loads(x) for x in merge_requests_file.readlines()]

    with open(ISSUES_FILE, "r") as issues_file:
        issues = [json.loads(x) for x in issues_file.readlines()]

    migrate_issues(issues, settings)
    migrate_merge_requests(merge_requests, settings)

if __name__ == "__main__":
  main()
