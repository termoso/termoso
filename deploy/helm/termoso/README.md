# Termoso Helm chart

Runs `termoso-server` on Kubernetes. By default it also runs a single-node Postgres, Redis and RustFS (S3) next to the API with the same images as `deploy/docker-compose.yml`; for production point `database`, `redis` and `s3` at managed services and switch `bundled.*.enabled` off.

```sh
helm install termoso deploy/helm/termoso \
  --namespace termoso --create-namespace \
  --set secrets.TERMOSO_MASTER_KEY="$(openssl rand -base64 32)" \
  --set config.TERMOSO_PUBLIC_URL=https://termoso.example.com \
  --set config.TERMOSO_WEBAUTHN__RP_ID=termoso.example.com \
  --set config.TERMOSO_ADMIN_EMAILS=you@example.com \
  --set bundled.postgres.password="$(openssl rand -hex 16)" \
  --set bundled.rustfs.secretKey="$(openssl rand -hex 16)" \
  --set ingress.enabled=true --set ingress.hosts[0].host=termoso.example.com
```

Every `TERMOSO_*` variable from `deploy/.env.example` is accepted: plain ones under `config`, secret ones under `secrets` (or bring your own Secret through `existingSecret`). The API runs read-only, non-root, with `termoso-server --healthcheck` as liveness and readiness probe. `metrics.enabled` opens the private Prometheus listener on the pod and `metrics.serviceMonitor.enabled` adds a ServiceMonitor.

Upgrades: `helm upgrade termoso deploy/helm/termoso --reuse-values --set image.tag=0.12.0`; migrations run on start, see docs/self-hosting/upgrading.
