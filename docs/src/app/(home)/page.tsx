import { OperatorHome } from '@weebo/operator-docs/site';
import { site } from '@/lib/shared';

export default function HomePage() {
  return (
    <OperatorHome
      site={site}
      label="Kubernetes operator · BatleHub"
      caption="Drive BatleHub, the package registry proxy-cache, from Kubernetes: its instances today, then its configuration, registries, package governance and maintenance — with GitOps-friendly status."
      actions={[
        { href: '/docs/guides/install', label: 'Get started', primary: true },
        { href: '/docs', label: 'Read the docs' },
      ]}
      install={`helm install weebo-batlehub \\
  oci://ghcr.io/batleforc/charts/weebo-batlehub \\
  --namespace weebo-batlehub --create-namespace \\
  --set certManager.issuerRef.name=<issuer>`}
      example={{
        title: 'Connect an instance',
        yaml: `apiVersion: batlehub.weebo.io/v1alpha1
kind: BatleHubLocalInstance
metadata:
  name: main
  namespace: team-a
spec:
  url: https://batlehub.example.com
  tokenSecretRef: { name: batlehub-admin, key: token }`,
      }}
      features={[
        {
          title: 'Connect instances',
          body: 'A BatleHubLocalInstance points at a BatleHub; the operator checks it answers and that its token carries the admin role.',
          href: '/docs/guides/connect-instance',
          link: 'Connect an instance',
        },
        {
          title: 'Secrets opt in',
          body: 'The operator only reads a token from a Secret labelled for it: nobody can make it send another Secret of the namespace to a URL of their choosing.',
          href: '/docs/guides/connect-instance#the-token-secret-opts-in',
          link: 'Token Secret',
        },
        {
          title: 'On the weebo kit',
          body: 'Same status, Events, metrics, chart and release pipeline as every weebo operator.',
          href: '/docs/reference/reason-codes',
          link: 'Reason codes',
        },
      ]}
    />
  );
}
