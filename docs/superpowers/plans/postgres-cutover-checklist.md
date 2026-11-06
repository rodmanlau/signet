# Cut over Signet to Postgres

Move the public app `signet` from the JSON files on its Fly volume to Managed Postgres. Allow and Revoke stay the same for the person at the browser.

Leave `DATABASE_URL` unset for local and dev runs. The process then keeps sessions in the `SIGNET_SESSIONS` file and grants in `agent-grants.json` beside that file.

Keep the volume for one clean week after cutover. Do not delete the volume in this change. The JSON files are the rollback copy.

## Create the cluster

Create Managed Postgres in `iad`. Use the Basic plan. The command prints a cluster id. `fly mpg list` prints it again.

```text
fly mpg create --region iad --name signet-pg --plan basic
```

## Stop traffic

Stop the app before `fly mpg attach`. Attach sets `DATABASE_URL` and deploys. A deploy before the import boots Signet on an empty database, and every saved session fails until the import finishes.

`min_machines_running` is 1, so Fly may start a machine again after you stop it. Stop each machine that `fly machines list --app signet` still shows as started.

```text
fly machine stop <machine-id> --app signet
```

Copy the volume files while a machine is up, then stop that machine again before the import. On the machine the paths are `/data/sessions.json` and `/data/agent-grants.json`.

```text
fly ssh console --app signet -C "cat /data/sessions.json" > sessions.json
fly ssh console --app signet -C "cat /data/agent-grants.json" > agent-grants.json
fly machine stop <machine-id> --app signet
```

If `agent-grants.json` is missing, skip that copy. The import treats a missing grants file as no grants.

If a request writes a session after the copy, copy the files again and stop the machine again. Then run the import again. A second run with the same files is safe.

## Set DATABASE_URL

`fly mpg attach` writes the `DATABASE_URL` secret on app `signet` and deploys. Do not put `DATABASE_URL` in `fly.toml`.

Run the import in the next section before this command. If you already attached, stop the machine again and finish the import before the app serves traffic.

```text
fly mpg attach <cluster-id> --app signet
```

To set the secret yourself, use the pooled URL from the cluster connection page. Keep that URL out of `fly.toml` and out of git.

```text
fly secrets set DATABASE_URL="<pooled-url>" --app signet
```

## Import the JSON files

From a checkout of this repository, point `DATABASE_URL` at the cluster. Use `fly mpg proxy` when the import runs on your machine. On the app machine, `--sessions` is `/data/sessions.json`.

```text
DATABASE_URL="<url>" node scripts/import-json-to-postgres.mjs --sessions /data/sessions.json --check
```

Omit `--grants` to read `agent-grants.json` in the same directory as the sessions file. Pass `--grants` when the copy lives somewhere else.

```text
DATABASE_URL="<url>" node scripts/import-json-to-postgres.mjs --sessions sessions.json --grants agent-grants.json --check
```

The command prints `sessions=N grants=M`. Those numbers are the row counts after the upsert. `--check` exits 0 when the counts equal the records in the files. It exits 1 when they do not.

The script upserts each session by id. It upserts a grant when the public key is new or the stored owner is the same. When the stored owner is different, the run exits non-zero and writes nothing from that run. Run it again after you fix the file.

## Start Signet

Start the machine with `DATABASE_URL` set. The attach deploy does this when you left it for last. If the machine is stopped, start it.

```text
fly machine start <machine-id> --app signet
```

## Confirm

Sign in and open `/connect` for an audience whose origin matches the return URL. The response includes `#signet-proof=`.

Allow an agent, then `POST /agent-proof` for that key. The response status is 200.

Grants written after this stay in Postgres. The import does not change the JSON files. Those files remain the pre-cutover copy.

## Keep the volume

Leave the volume mounted for one clean week. Do not delete it in this change.

## Roll back

Unset `DATABASE_URL` and let Fly restart the app. `fly.toml` still sets `SIGNET_SESSIONS` to `/data/sessions.json`. With `DATABASE_URL` unset, the process reads that file and `agent-grants.json` beside it.

```text
fly secrets unset DATABASE_URL --app signet
```

Sessions and grants created after the import exist only in Postgres. Rollback does not copy them back into the JSON files.
