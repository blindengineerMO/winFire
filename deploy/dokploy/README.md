# Dokploy deployment files

`docker-compose.yml` is the checked-in source used by `npm run deploy:dokploy`.
The helper configures it as a Dokploy Docker Compose application with three
services: `api`, `ui`, and `postgres`. Each service starts with one replica.

The wizard uses Dokploy's generic Git source with the supplied public GitHub URL;
this keeps deployments repeatable without requiring a GitHub OAuth provider on
the Dokploy instance.

The UI is the public service and proxies `/api` to the API container. Dokploy
creates the UI domain only after the compose application exists, so the helper
creates the compose app, saves its generated environment, attaches the random
hostname to the `ui` service, and then deploys.

The current WinFire API migration engine is SQLite based. The stack keeps the
API data volume durable and exposes the PostgreSQL connection as `POSTGRES_URL`
for the database adapter migration. PostgreSQL is provisioned and health
checked now; switching the API storage engine is a separate migration step.
