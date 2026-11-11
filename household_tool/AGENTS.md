# Household Tool

Start with `docs/project-wiki/README.md` and its linked pages before changes.
Keep documentation aligned with migrations, routes and actual release state.
Use isolated `HOUSEHOLD_DATA_DIR` for tests, never production `/data`.
Run `python -m unittest discover -s tests -v` with app requirements and httpx.
The sibling `downtime/` add-on belongs to a separate workstream.
Do not stage local-data, options.json, credentials, caches or unrelated changes.
