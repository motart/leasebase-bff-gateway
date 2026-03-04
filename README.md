# LeaseBase bff-gateway

API composition layer and auth middleware (BFF pattern). Routes external requests to internal microservices.

## Stack

- **Runtime**: Node.js / NestJS (planned)
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
