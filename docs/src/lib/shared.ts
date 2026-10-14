import { defineSite } from '@weebo/operator-docs/site';

// What makes this site weebo-batlehub's; everything else comes from
// @weebo/operator-docs.
export const site = defineSite({
  name: 'weebo-batlehub',
  description:
    'Drive BatleHub instances — configuration, registries, governance and maintenance — as Kubernetes resources.',
  git: {
    user: 'batleforc',
    repo: 'weebo-batlehub',
    branch: 'main',
    contentDir: 'docs/content/docs',
  },
});
