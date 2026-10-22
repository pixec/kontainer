# Kontainer runner Helm chart

A build runner for a [Kontainer](../../../README.md) registry: it claims queued builds of the
namespaces it serves and runs each as a Kubernetes Job next to a rootless BuildKit.

Register the runner in the registry first (your user or organization settings → **Runners**, or
**Admin → Runners** for a shared one) to get its token, then:

```sh
helm install kontainer-runner deploy/helm/kontainer-runner -n builds --create-namespace \
  --set server=https://registry.example.com --set token=kr_... \
  --set image.repository=registry.example.com/kontainer
```

See [values.yaml](values.yaml) and [docs/builds.md](../../../docs/builds.md).
