import os

import requests

GITHUB_TOKEN = os.environ["GH_TOKEN"]
OWNER = "beesyst"
PROJECT_NUMBER = 1
README_PATH = "README.md"

COLUMNS = [
    ("Todo", "Todo"),
    ("In Progress", "In Progress"),
    ("Done", "Done"),
]

QUERY = """
query($login: String!, $number: Int!) {
  user(login: $login) {
    projectV2(number: $number) {
      id
      title
      items(first: 100) {
        nodes {
          content {
            ... on Issue { title }
            ... on PullRequest { title }
            ... on DraftIssue { title }
          }
          fieldValues(first: 20) {
            nodes {
              ... on ProjectV2ItemFieldSingleSelectValue {
                name
              }
              ... on ProjectV2ItemFieldTextValue {
                text
              }
            }
          }
        }
      }
      fields(first: 20) {
        nodes {
          ... on ProjectV2FieldCommon {
            name
            id
          }
        }
      }
    }
  }
}
"""


def get_project_tasks():
    url = "https://api.github.com/graphql"
    headers = {"Authorization": f"bearer {GITHUB_TOKEN}"}
    variables = {"login": OWNER, "number": PROJECT_NUMBER}
    response = requests.post(
        url, json={"query": QUERY, "variables": variables}, headers=headers
    )
    data = response.json()

    if "errors" in data:
        print("GraphQL Errors:", data["errors"])
        raise Exception("GraphQL request failed")

    project = data["data"]["user"]["projectV2"]
    items = project["items"]["nodes"]

    status_field = None
    for field in project["fields"]["nodes"]:
        if field["name"].lower() == "status":
            status_field = field["id"]
            break

    tasks = {col[0]: [] for col in COLUMNS}
    for item in items:
        title = None
        if item["content"]:
            title = item["content"].get("title") or item["content"].get("text")
        if not title:
            continue
        status = None
        for field_value in item["fieldValues"]["nodes"]:
            if "name" in field_value and field_value["name"] is not None:
                status = field_value["name"]
        for col_name, gh_name in COLUMNS:
            if status == gh_name:
                tasks[col_name].append(title)
                break
    return tasks


def render_kanban_md(tasks):
    counts = {col: len(tasks[col]) for col, _ in COLUMNS}
    max_items = 10

    headers = [f"{col} ({counts[col]})" for col, _ in COLUMNS]
    md = "| " + " | ".join(headers) + " |\n"
    md += "| " + " | ".join(["---"] * len(COLUMNS)) + " |\n"

    for i in range(max_items):
        row = []
        for col, _ in COLUMNS:
            if i < len(tasks[col]):
                row.append(tasks[col][i])
            else:
                row.append("&nbsp;")
        md += "| " + " | ".join(row) + " |\n"
    return md


def update_readme(kanban_md):
    with open(README_PATH, encoding="utf-8") as f:
        lines = f.readlines()
    start, end = None, None
    for idx, line in enumerate(lines):
        if "<!--KANBAN_START-->" in line:
            start = idx
        if "<!--KANBAN_END-->" in line:
            end = idx
    if start is not None and end is not None and end > start:
        new_lines = lines[: start + 1] + [kanban_md + "\n"] + lines[end:]
    else:
        new_lines = [
            "<!--KANBAN_START-->\n",
            kanban_md + "\n",
            "<!--KANBAN_END-->\n",
        ] + lines
    with open(README_PATH, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


if __name__ == "__main__":
    tasks = get_project_tasks()
    kanban_md = render_kanban_md(tasks)
    update_readme(kanban_md)
    print("Kanban board updated in README.md")
