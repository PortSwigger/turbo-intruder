# MCP Server Quick Reference

## Starting the Server

**Standalone mode:**
```bash
java -jar build/libs/turbo-intruder.jar --mcp
```

**Burp extension:** Auto-starts when extension loads.

Server listens on `localhost:31337` using streaming HTTP transport.

---

## Available Tools

| Tool | Description |
|------|-------------|
| `start_run` | Start a run and block until it completes or `timeout_ms` elapses |
| `start_run_async` | Start a run and return immediately with a `run_id` |
| `stop_run` | Stop a run, preserving its results |
| `delete_run` | Remove a run and its results |
| `save_to_organizer` | Save selected requests from a run to Burp's Organizer |
| `report_finding` | Record a structured finding (severity/confidence/type + evidence request) to Burp's Organizer |
| `generate_collaborator_payload` | Generate a Burp Collaborator payload for out-of-band testing |
| `get_collaborator_interactions` | Retrieve Collaborator interactions for generated payloads |
| `search_responses` | Search a run's responses/labels for a string |

**Tool parameters for start_run / start_run_async:**
- `script` - Python script with `queueRequests(target, wordlists)` and `completed(results)` functions
- `base_request` - HTTP request template with `%s` injection points
- `endpoint` - Target URL (e.g., `https://example.com:443`)
- `base_input` - Optional input data for the script
- `timeout_ms` - (`start_run` only) how long to block before returning a `run_id` for polling

### Running long runs without blocking

`start_run_async` returns a `run_id` immediately. Observe progress and completion by
reading `turbo://runs/{run_id}?wait=true`, which long-polls until the run finishes (up
to ~50s per read; read again to keep waiting). The stateless HTTP transport has no
sessions, so the server cannot *push* completion notifications — observation is always
client-driven via this resource.

---

## Available Resources

| URI | Description |
|-----|-------------|
| `turbo://runs` | List all runs |
| `turbo://runs/{id}` | Run status |
| `turbo://runs/{id}/summary` | Query summary (supports `?sort_by=`, `?limit=`, `?offset=`) |
| `turbo://runs/{id}/{n}` | Full request/response detail (supports `?body_limit=`, `?export=file`) |

Use `current` as the run ID to reference the most recent run.

### Documentation Resources

| URI | Description |
|-----|-------------|
| `turbo://docs` | List available documentation topics |
| `turbo://docs/api-quickstart` | Quick reference for scripting |
| `turbo://docs/engines` | Engine types (THREADED, BURP, BURP2) |
| `turbo://docs/settings` | Complete parameter reference |
| `turbo://docs/race-conditions` | Race condition testing with gates |
| `turbo://docs/response-processing` | Handling and filtering responses |
| `turbo://docs/decorators` | Response decorator reference |
| `turbo://docs/misc` | Wordlists and utilities |
