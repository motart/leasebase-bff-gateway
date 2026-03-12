# LeaseBase bff-gateway

API gateway / reverse proxy (BFF pattern). Routes external requests to internal microservices. **Does not perform authentication or role resolution** — auth is handled by each downstream service via `@leasebase/service-common` `requireAuth` middleware.

## Stack

- **Runtime**: Node.js / Express + http-proxy-middleware
- **Container**: Docker -> ECS Fargate
- **Registry**: ECR `leasebase-{env}-v2-bff-gateway`
- **Port**: 3000

## Infrastructure

Managed by Terraform in [leasebase-iac](https://github.com/motart/leasebase-iac).

## Getting Started

```bash
npm install
npm run start:dev
docker build -t leasebase-bff-gateway .
npm test
```


---

## Docker Tagging Strategy

Every CI build on `develop` pushes **two Docker image tags** to Amazon ECR:

- **`dev-latest`** — moving tag that always points to the most recent develop build. ECS services are configured to deploy this tag.
- **`<git-sha>`** — immutable tag using the full 40-character commit SHA, retained for traceability and rollback.

**ECS deployments** reference `dev-latest`. After pushing, the pipeline registers a new ECS task definition with `dev-latest` and forces a new deployment.

**Rollbacks**: to roll back to a previous build, update the ECS task definition to reference the specific `<git-sha>` tag of the desired commit.
