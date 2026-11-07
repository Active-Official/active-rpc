import yaml, pathlib
data = yaml.safe_load(open(".github/workflows/ci.yml", encoding="utf-8"))
run = [s["run"] for s in data["jobs"]["fuzz"]["steps"] if "run" in s and "targets=" in s["run"]][0]
pathlib.Path(r"C:\Users\Usuario\AppData\Local\Temp\grok-goal-e7b594acfea1\implementer\campaign.sh").write_text(run, encoding="utf-8")
print(len(run.splitlines()), "lines")
