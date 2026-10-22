# Kontainer Helm chart

Kontainer, an OCI registry with accounts, RBAC, scanning, builds from Git and a layer-inspection
UI, as a single-replica Deployment with a persistent volume.

```sh
docker build -t registry.example.com/kontainer:0.2.0 . && docker push registry.example.com/kontainer:0.2.0
helm install registry deploy/helm/kontainer -n registry --create-namespace \
  --set image.repository=registry.example.com/kontainer \
  --set ingress.enabled=true --set ingress.host=registry.example.com --set ingress.tls.enabled=true
```

Every value is described in [values.yaml](values.yaml); [docs/deployment.md](../../../docs/deployment.md)
covers storage, builds, metrics and settings passed as `KONTAINER__SECTION__KEY` variables.
