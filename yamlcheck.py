import sys
try:
    import yaml
except ImportError:
    print("no pyyaml")
    sys.exit(0)
for path in (".github/workflows/ci.yml", ".github/workflows/fuzz-nightly.yml"):
    data = yaml.safe_load(open(path, encoding="utf-8"))
    print(path, "ok, jobs:", list(data.get("jobs", {})))
    if "fuzz" in data.get("jobs", {}):
        steps = data["jobs"]["fuzz"]["steps"]
        run = [s for s in steps if "run" in s and "targets=" in s["run"]]
        if run:
            print("  campaign step starts:", run[0]["run"].splitlines()[0])
