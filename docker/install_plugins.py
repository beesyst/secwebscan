import json
import os

CONFIG_PATH = "/tmp/config.json"
SCRIPT_PATH = "/tmp/tools_install.sh"

with open(CONFIG_PATH) as f:
    config = json.load(f)

seen = set()
commands = []

for plugin in config.get("plugins", []):
    if plugin.get("enabled") and plugin.get("install"):
        for cmd in plugin["install"]:
            if cmd not in seen:
                commands.append(cmd)
                seen.add(cmd)

with open(SCRIPT_PATH, "w") as f:
    f.write("#!/bin/bash\nset -e\n\n")
    for cmd in commands:
        f.write(f"echo '🔧 Installing: {cmd}'\n")
        f.write(cmd + "\n")

os.chmod(SCRIPT_PATH, 0o755)
