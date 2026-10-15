# weebo-batlehub : cahier des charges (v2, sur weebo-operator-kit)

Ce document décrit l'opérateur Kubernetes qui pilote
[batlehub](https://github.com/batlehub/batlehub) (proxy-cache de
registries de paquets), réécrit sur **weebo-operator-kit**. Il part de
l'inventaire de la première version (`github.com/batlehub/operator`,
conservé tel quel dans `batlehub.v0.1.md`), le passe en revue et l'adapte
aux conventions des opérateurs weebo (`docs/plan.md` du kit, gabarit
`templates/operator`, weebo-forgejo comme référence).

Il se suffit à lui-même : c'est le cahier des charges de la réécriture.
Le §1 dit ce qui change par rapport à la v0.1 et pourquoi ; la suite est
la spécification.

La v0.1 n'a jamais été déployée (aucun CR `batlehub.io` dans les dépôts
gitops) : pas de chemin de migration à écrire, l'importeur (M5) part
d'une release Helm de batlehub, pas de la v0.1.

Références : batlehub **v1.4.0** au moment de l'écriture (crate
`batlehub-config`, chart Helm `helm/batlehub` 1.4.0, image
`ghcr.io/batlehub/batlehub`), **v1.5.0** visée pour D4 (§11.1) mais qui
ne les porte pas (Constats du M1), **v1.6.0** qui les porte (RFC 0037 de
batlehub, D8 révisée) et sur laquelle tout est épinglé depuis le M2 ; kit
**v0.14.2** (M0), **v0.14.3** (M1), **v0.15.0** (M2).

### Historique

- **v2.2 — M2, 2026-10-15** : batlehub **v1.6.0** publie D4 sous la forme
  de son RFC 0037, qui diffère de la première esquisse de ce document :
  `merge_layers` rend un **document TOML canonique** (`String`, clés
  triées, `${VAR}` gardés, `$` littéral écrit `\u0024`) et non un
  `toml::Value` ; `validate_layers(layers, &dyn Fn(&str) -> Option<String>)` ;
  et à la place de `RESTART_KEYS` une **allowlist** `reload_keys::RELOAD_KEYS`
  (tiers `Hot`/`Partial`/`Restart`, toute clé absente = redémarrage) avec
  `reload_keys::classify(avant, après)`. D8, 2.2, 2.4 et §11.1 suivent ;
  le M2 est livré (Constats du M2).
- **v2.1 — revue du 2026-10-14** (relecture « prêt à implémenter ? »
  contre le kit v0.14, les correctifs de forgejo/authentik du 2026-10-13
  et le code de batlehub) :
  - instance : le kind namespacé devient `BatleHubLocalInstance` (D5),
    rôle `LocalInstance` du kit comme `ForgejoLocalInstance` et
    `AuthentikLocalInstance` ; `instanceRef`/`status.instance` sont les
    types du kit (`InstanceRef`, `BoundInstance`), résolution par
    `resolve_bound`/`check_binding`, codes `Instance*` du gabarit (§2.8) ;
  - opt-in des Secrets envoyés ailleurs : labels `instance-token` et
    `credential`, TLS limité au namespace de l'instance (§2.11) ;
  - D4 appliqué : prérequis du M2, batlehub v1.5.0, validation avec
    l'environnement de l'instance (§2.2, §11.1) ;
  - modes namespacés du chart supportés par refus (§7.1, D6) ;
  - mapping des réponses par endpoint, requeue « steady », `Gone` contre
    référence absente (§2.10) ;
  - écriture incrémentale du status des grants, `InstanceInUse`,
    collisions de registries, pas d'adoption implicite des objets
    possédés, contrôle du rôle du jeton par `/api/v1/me` ;
  - §5 complet ; CI et release du kit (`publish.yml`, porte e2e, test
    d'upgrade) ; alpha au M2 (D7) ; jalons revus ;
  - D5–D9 acceptées le 2026-10-14 (D8 : batlehub v1.5.0 confirmée).
- **v2 — 2026-10-12** : réécriture sur le kit v0.9.0, D1–D4 acceptées.

Vocabulaire :

- **batlehub** : le proxy-cache géré. Une instance lit un fichier de
  config TOML (plusieurs `--config` possibles, fusionnés), expose une API
  admin sous `/api/v1/admin/*` (OpenAPI générée par utoipa,
  `batlehub dump-spec`) et sait recharger sa config à chaud.
- **Instance** : un processus batlehub, ou l'ensemble des pods qui le
  font tourner. Côté Kubernetes, un `BatleHubLocalInstance` (namespacé, D2, D5).
- **Rôles** : un processus batlehub tourne en `proxy`, `worker` (scan de
  vulnérabilités) ou les deux (`--roles proxy,worker`).

## 1. Review de la v0.1

### 1.1 Ce qui est bon et qu'on garde

Le fond métier de la v0.1 est solide, et c'est la partie qui coûte le
plus à redécouvrir. On le reprend presque mot pour mot :

- le CRD ne reprend jamais le schéma de config de batlehub (objet ouvert,
  validé par le vrai parser) ;
- une seule liste des clés à redémarrage, deux hashs (config complète /
  clés à redémarrage) ;
- l'opérateur est l'admin qui approuve les reloads, pod par pod, par IP ;
  le nonce de re-stage, le backoff des refus, la stratégie `Manual` ;
- le token opérateur généré une fois, déclaré par son hash Argon2id, la
  détection du masquage par la couche `credentials` ;
- les refus de l'API admin deviennent un état, pas une boucle d'erreur ;
- « au plus une fois » pour les maintenances, `dryRun` vrai par défaut ;
- les règles de gouvernance (l'objet ne gère que ce qu'il a écrit, dérive
  détectée par relecture, exemptions portées par la policy de version) ;
- l'interdiction de `${` dans une registry venue d'un autre namespace ;
- server-side apply sur les objets possédés, RBAC sans `update`.

### 1.2 Ce qui change pour suivre le kit

| Sujet | v0.1 | v2 | Pourquoi |
| --- | --- | --- | --- |
| Architecture | « cœur fonctionnel, coquille impérative », **pas de ports**, 3 modules (`api`, `client`, `controller`) | Hexagonal du kit : `domain`, `api`, `application` (ports + use cases), `adapters-outbound`, `adapters-inbound`, `operator`, `crdgen`, `testkit`, plus `batlehub-client` généré | Même découpage et mêmes règles de dépendance que tous les opérateurs weebo ; les ports permettent les fakes de `application::test_support` et les tests de use cases en millisecondes |
| Client admin | Écrit à la main, une méthode par endpoint | **Généré** depuis l'OpenAPI de batlehub (`batlehub dump-spec` → `spec/batlehub-vX.Y.Z.json` + correctifs `jq`), jamais édité à la main, comme `forgejo-client` | batlehub publie déjà son OpenAPI (utoipa) ; la montée de version devient `task gen:bump` |
| Groupe, noms | `batlehub.io`, `batlehub-operator`, `BatleHub` | `batlehub.weebo.io`, `weebo-batlehub`, `BatleHubLocalInstance` namespacé (voir §3) | Convention `<produit>.weebo.io` ; kind d'instance namespacé (D2) nommé selon le rôle `LocalInstance` du kit, comme forgejo et authentik (D5) |
| Status | `phase` + 7 types de condition par kind | Condition `Ready` (une raison du catalogue `reason_codes!`) + conditions advisory du kit ; pas de `phase` | Modèle de status commun : la page « Reason codes » de la doc, les Events, les métriques et le health check Argo CD du chart du kit ne lisent que `Ready` et ses raisons |
| Codes de raison | Chaînes libres par condition | Un seul `domain::error::ReasonCode` (§5) | « Aucune chaîne de raison en dur au point d'appel » |
| Events | `ConfigReloaded`, `ReconcileFailed`… émis à la main | `events::announce_outcome` (Warning à chaque `Ready: False`, Normal à chaque changement), `announce_change` pour les étapes hors condition, `retry_after_error` pour les erreurs avant status | Le kit |
| Leader election | Réimplémentée (bail 15 s, deadline 10 s, retry 2 s, exit) | `weebo_kit_runtime::leader` | Écritures gardées par `resourceVersion`, expiration sur horloge monotone : déjà résolu une fois |
| Webhook | Serveur TLS propre, certificat généré par le chart (`lookup`) | `webhook_server` + `admission::router` + trait `Admission` ; certificat cert-manager du chart du kit | Échec fermé, `DELETE`/`UPDATE` sans changement de `spec` toujours acceptés, compteur `_webhook_decisions_total` : exactement les règles de la v0.1 |
| Avertissements du webhook | Réponses `warnings` | Retirés en v1alpha1 : ils sont déjà dans le status (advisories) | Le trait `Admission` du kit ne rend qu'un refus ; l'ajouter est une évolution du kit (§11.2) |
| Contrôleur | Watch brut + règle « une passe qui ne change rien n'écrit pas de status » | `weebo_kit_runtime::controller` : prédicats generation/annotations/labels/finalizers, concurrence bornée, gigue, `requeue_after` | Le status n'est plus un déclencheur : la règle de la v0.1 devient inutile |
| Métriques | `batlehub_*` | Préfixe `weebo_batlehub_` : `ReconcileMetrics` du kit + jauges propres (§6.11) | Pages de doc et alertes du chart du kit dérivées du préfixe |
| Flags | `BATLEHUB_OPERATOR_*` | Variables du kit (`WEEBO_METRICS_ADDR`, `LOG_FORMAT`, `WEEBO_RECONCILE_CONCURRENCY`, `POD_NAMESPACE`, `LEASE_NAME`, `WEBHOOK_*`…) + `WEEBO_BATLEHUB_*` pour les siennes | Contrat du kit |
| Chart | Chart complet écrit à la main | `templates/operator.yaml` + `_params.tpl` sur `weebo-operator-lib` ; contrat de values du kit + clés propres | Même chart pour tous ; CRD en templates `crds.install` + `keep` |
| CRD trop gros pour `kubectl apply` | « installés au premier install seulement, appliquer en SSA à l'upgrade » | Réglé par `helm:crds` du kit (CRD en templates Helm) | Plus de procédure manuelle |
| Références | `Delete`/`Retain`, `caBundleSecretRef`, `insecureSkipTlsVerify`, `instanceRef` maison | `deletionPolicy: Delete`/`Orphan` (type de l'`api` de l'opérateur, comme `api/src/common.rs` de forgejo : le kit n'en a pas), TLS et références de Secret du namespace de l'instance (types du kit `LocalTlsOptions`/`LocalSecretKeyRef`, dont le nom n'apparaît pas dans le schéma), `instanceRef` de l'opérateur (§2.8) | Mêmes noms de champs que forgejo/authentik |
| Tests d'intégration | apiserver en mémoire fait maison | `weebo-kit-testkit` (envtest) + fakes de ports ; contrat wiremock sur le client généré ; tests live contre un vrai batlehub | Un harnais de moins à maintenir |
| Qualité | Couverture ≥ 95 %, complexité, score de détecteurs | `task coverage` du kit (≥ 85 %), `clippy -D warnings`, budget de ressources `weebo-kit-perf` | Seuils communs ; le budget mesure ce qui compte pour un opérateur |
| Outillage | Ad hoc | Taskfile + tâches distantes du kit, mise, cocogitto (`templates/cog.toml`), `checks.yml`, `perf.yml`, doc `@weebo/operator-docs` | Contrat de chaque repo weebo |

### 1.3 Ce qui disparaît

- **Mode limité à un namespace façon v0.1** (`watchNamespace`, repli de
  `Selector` sur `Same` avec avertissement) : remplacé par le scope du
  kit (`watch.namespace`, `watch.labelSelector`, `clusterKinds`,
  `WatchScope`), que le chart et le gabarit rendent déjà. Ce que batlehub
  refuse dans ces modes : §7.1 (D6).
- **Build sans le parser** (air-gap, validation locale désactivée) : une
  combinaison de build que la CI ne teste pas. Le parser est une
  dépendance git épinglée, vendorable comme le reste (`cargo vendor`).
- **Réimplémentation de la fusion des couches « bit à bit »** : la
  fusion existe déjà dans `batlehub-config` ; on l'appelle (§2.3).
- **Annotation `admin-url` + `--allow-admin-url`** pour joindre une
  instance managed depuis l'extérieur : les tests envtest utilisent une
  instance `external` vers un wiremock, le développement local un
  `kubectl port-forward` vers une instance `external`. Moins de surface
  pour faire fuiter le token.
- **`status.phase`, `status.mode`** : remplacés par `Ready` et sa raison
  (colonnes kubectl `READY`/`REASON` comme les autres opérateurs) ; le
  mode se lit dans la spec.

### 1.4 Ce qui manquait à la v0.1

- **Collision sur la gouvernance** : deux `BatleHubPackageGrant` sur la
  même coordonnée et le même sujet se réécrivaient l'un l'autre, et un
  grant déjà posé par la console était écrasé sans rien dire. v2 : règle
  de forgejo, « rejet, jamais d'adoption implicite » (§4.6), adoption par
  l'importeur seulement.
- **Ordre de livraison** : la v0.1 a tout livré d'un coup et n'a jamais
  fait tourner son e2e ni sa release jusqu'au bout. v2 : jalons (§10),
  chacun validé contre un vrai batlehub, avec ses constats écrits dans ce
  document comme forgejo le fait.
- **Ce qu'on demande à batlehub** : plusieurs mécanismes subtils de la
  v0.1 (nonce de re-stage, fusion recopiée, liste de clés à redémarrage
  recopiée de la doc) contournent des manques de batlehub, que nous
  maintenons aussi. §11.1 liste les évolutions upstream qui les
  simplifient : celles de D4 (`merge_layers`, `validate_layers`,
  `RESTART_KEYS`, devenue `reload_keys`) étaient un **prérequis du M2**,
  livrées par batlehub v1.6.0 ; les autres sont facultatives.

### 1.5 Décisions

D1–D4 ont été tranchées le 2026-10-12 ; D5–D9, proposées par la revue
du 2026-10-14, ont été acceptées le même jour.

| # | Décision | Retenu |
| --- | --- | --- |
| D1 | Garder le mode **managed** (l'opérateur déploie batlehub) ou se limiter à piloter une instance déployée par le chart Helm de batlehub ? | Garder les deux, mais **managed en dernier** (M4) : external + gouvernance sont la forme naturelle d'un opérateur weebo (piloter un système existant) et livrent de la valeur sans recopier le chart. Le managed est la moitié du code et du CRD (~270 Ko). |
| D2 | L'instance namespacée (v0.1) ou cluster-scoped (gabarit, forgejo) ? | **Namespacé** : le mode managed possède Deployment/Service/PVC par owner reference, impossible depuis un objet cluster-scoped. Kind d'instance namespacé, nommé `BatleHubLocalInstance` (D5) ; pas de kind cluster-scoped en v1alpha1 (§2.8). |
| D3 | Renommer `BatleHubGrant`/`BatleHubPolicy` ? | Oui : `BatleHubPackageGrant`/`BatleHubPackagePolicy`. Ce qu'ils couvrent (niveaux paquet et version) se lit dans le nom, et `…Policy` seul se confond avec les `<Produit>NamespacePolicy` des autres opérateurs. |
| D4 | Pousser les évolutions de §11.1 dans batlehub avant le M2 ? | Au moins `merge_layers`/`validate_layers` et `RESTART_KEYS` (petites, sans risque) ; le reload par hash si le protocole §6.1 s'avère fragile en M2. |

| # | Décision (revue du 2026-10-14) | Retenu |
| --- | --- | --- |
| D5 | Nommer le kind namespacé `BatleHubLocalInstance` (rôle `LocalInstance` du kit) ? | **Acceptée** (2026-10-14) : même convention que `ForgejoLocalInstance`/`AuthentikLocalInstance` et le gabarit ; `InstanceRef`, `BoundInstance`, `read_local_instance_token`, `LocalSecretKeyRef`, `LocalTlsOptions` et les codes du gabarit servent tels quels (§2.8). Un `BatleHubInstance` cluster-scoped pourra venir plus tard (hors v1alpha1). |
| D6 | Modes `watch.namespace` / `clusterKinds: false` du chart du kit | **`watch.namespace` supporté par refus** (§7.1) : pas de registry cross-namespace, pas de ClusterRoleBinding TokenReview, pas de watch des Namespaces. **`clusterKinds: false` à refuser par le chart** tant que le kit n'a pas de règles propres pour le Role `-watch` (§11.2) — **pas faisable** (le kit fait un rendu de fumée de ce mode, Constats du M0 et du M2) : le mode est documenté comme partiel (values, guide d'installation). `clusterSecrets: true` posé explicitement. |
| D7 | Première release | **0.1.0-alpha.1 au M2** (external + `manageConfig`), pour éprouver `publish.yml`, la porte e2e et le test d'upgrade tôt ; 0.1.0 au M5. |
| D8 | Version de batlehub pour D4 | ~~v1.5.0~~ (ne les portait pas) → **v1.6.0** (révisée le 2026-10-15) : `merge_layers` → document canonique, `validate_layers(layers, &dyn Fn)`, `reload_keys::{RELOAD_KEYS, classify}` (RFC 0037 de batlehub) ; `batlehub-config` épinglé sur ce tag ; `task gen:bump` déplace ensemble spec, client, tag de `batlehub-config` et images des tests. |
| D9 | Watch des Secrets en métadonnées (6.7) | **Le retirer** : `list/watch` sur `secrets` donne en RBAC le droit de lire tous les Secrets (RBAC ne sait pas limiter aux métadonnées), ce que le kit n'accorde jamais. Les Secrets sont relus à chaque reconcile comme dans forgejo/authentik, et leur hash entre dans `configHash` : une rotation est vue à la resynchronisation (≤ 300 s ±20 %), ou tout de suite si le CR change. Le watch des ConfigMaps en métadonnées reste. |

## 2. Choix structurants

### 2.1 Le CRD ne reprend jamais le schéma de config de batlehub

`spec.config` est un objet ouvert (`x-kubernetes-preserve-unknown-fields`) :
le fichier TOML de batlehub écrit en YAML, clé pour clé. Aucune clé n'est
typée dans le CRD.

- Tout paramètre accepté par batlehub est accepté par le CRD, par
  construction ; la couverture n'a pas à être maintenue champ par champ.
- Prix : la validation est déléguée au parser (2.2) et la version mineure
  de l'opérateur suit le schéma de config de batlehub.
- Même principe pour les policies de gouvernance (`PolicyDto` en objet
  ouvert, validé par l'instance) et pour `BatleHubRegistry.spec.config`.

### 2.2 La validation passe par le vrai parser de batlehub

La crate `batlehub-config` est une dépendance git épinglée sur un tag de
batlehub (`tag = "v1.4.0"`), comme le kit l'est pour l'opérateur.
`deny.toml` l'autorise (`[sources] allow-git`). Bumper ce tag est une
décision de compatibilité délibérée, faite avec `task gen:bump` (client
généré, image par défaut, parser ensemble), jamais un effet de bord.

Elle vit dans `adapters-outbound` derrière un port `ConfigParser`
(`application::ports`) : le domaine et les use cases ne voient que
« valide / invalide + message + warnings ». Une config refusée par le
parser est bloquée avant d'atteindre un pod : `Ready: False`,
`ConfigInvalid`, et refus du webhook.

`batlehub-config` 1.4.0 expose `load_from_str` et `load_layered_from_str`,
mais elles lisent **l'environnement du processus** (celui de
l'opérateur) à deux endroits : l'expansion des `${VAR}` et
`apply_env_overrides()` (appelé par `config_from_value`), qui applique
les 15 overrides `PROXY_CACHE__*` (§8). Valider avec elles donnerait le
verdict de l'environnement de l'opérateur, pas de l'instance ; et la
fusion reste privée (`merge_value`).

D4 (livré par batlehub v1.6.0, RFC 0037, D8) : `merge_layers` (la
fusion sans expansion, rendue en un document TOML canonique dont les
`${VAR}` restent des placeholders) et `validate_layers(layers, env)` où
`env` fournit **à la fois** les `${VAR}` et les `PROXY_CACHE__*` de
l'instance, jamais `std::env`. L'adaptateur `BatleHubConfigParser`
n'appelle que ces deux fonctions (plus la conversion YAML ↔ TOML des CRD
et la vérification du token, 6.3). Aucune substitution maison n'est
écrite.

### 2.3 La fusion des couches est celle de batlehub

batlehub accepte plusieurs `--config`. L'opérateur fusionne lui-même les
couches qu'il rend, pour hasher et valider le résultat, **en appelant la
fusion de `batlehub-config`** (pas une copie) :

- la couche la plus tardive gagne ;
- les tables se fusionnent récursivement ;
- les tableaux de tables se fusionnent entrée par entrée sur la clé
  `name`, sinon `type`, mais seulement si chaque entrée porte une valeur
  unique ; sinon le tableau entier est remplacé ;
- les scalaires sont remplacés ; `x = []` dans une couche tardive vide la
  liste.

Les couches rendues (`config`, `configLayers`, registries, bloc `[[auth]]`
de l'opérateur) sont fusionnées dans **un seul fichier**, pour que
`GET /admin/config/content` montre tout le document. Seule la couche
`credentials` reste un second `--config` séparé (6.4).

### 2.4 Une seule table des clés que le reload applique

La première esquisse listait huit clés à redémarrage ; le code de
batlehub en a une trentaine. batlehub v1.6.0 (RFC 0037) publie l'inverse,
une **allowlist** : `batlehub_config::reload_keys::RELOAD_KEYS`, par
motif de chemin (`registries[*].rbac`…), en trois tiers — `Hot` (tout
lecteur voit la nouvelle valeur), `Partial` (le chemin des requêtes oui,
un composant construit au démarrage non : warming, imports, worker),
`Restart` — **toute clé absente de la table est `Restart`**. batlehub
s'en sert lui-même (son `ReloadDiff` : `applied`, `partially_applied`,
`restart_required` contre la config de **démarrage**), l'opérateur ne la
recopie pas :

- **external** (M2) : la réponse du dry run `POST /admin/config/validate`
  donne `restart_required`, calculé par l'instance contre ce qu'elle a
  chargé au démarrage, couche credentials comprise. Non vide : le push est
  retenu (`RestartForbidden`, 6.6).
- **managed** (M4) : `reload_keys::classify(avant, après)` sur les
  documents de `merge_layers` alimente le hash de redémarrage (6.1) ;
  `Partial` est traité comme un redémarrage quand le travail de fond
  compte pour l'instance (réglage par instance, à trancher au M4).

### 2.5 Server-side apply pour les objets possédés

- Chaque objet possédé est écrit en server-side apply avec le field
  manager `weebo-batlehub-operator` (le même que les patchs de status du
  kit) : une modification d'un utilisateur et une de l'opérateur ne se
  battent jamais en silence sur le même champ.
- Merge patch sans field manager pour deux champs posés hors des applies :
  l'annotation `batlehub.weebo.io/approved-config-hash` et le
  `restartedAt` du pod template (action `restart`).
- **Exception** : le Secret du token opérateur est créé une fois (POST) et
  jamais ré-appliqué, pour qu'il ne tourne pas sous une instance en
  marche.
- RBAC : `create` et `patch`, jamais `update` (sauf `…/finalizers`, voir
  §7).
- Labels sur tout ce qui est créé : `app.kubernetes.io/name: batlehub`,
  `app.kubernetes.io/instance: <instance>`, `app.kubernetes.io/component`,
  `app.kubernetes.io/managed-by: weebo-batlehub` (même valeur que le
  label de propriété des Secrets du kit).

### 2.6 Placeholders `${VAR}`

- Résolus par l'instance, pas par l'opérateur.
- Pour valider, l'opérateur passe à `validate_layers` l'environnement
  qu'il connaît de l'instance (`env[].value`,
  `env[].valueFrom.secretKeyRef` de l'instance managed, `PROXY_CACHE__*`
  compris) et une valeur factice pour le reste, et liste les noms non
  résolus dans l'advisory `UnresolvedPlaceholders`. Les valeurs lues
  servent à la validation seulement : elles ne sont ni rendues ni
  envoyées, et n'apparaissent dans aucun message.
- `reload.validation: Lenient` existe pour le cas où c'est la valeur
  factice qui fait échouer la validation : le refus du parser devient
  l'advisory `ConfigInvalidLenient` au lieu de bloquer.

### 2.7 Deux modes, un seul contrat de config

Un `BatleHubLocalInstance` est soit **managed** (l'opérateur déploie et
possède le workload), soit **external** (instance existante joignable en
HTTP, typiquement déployée par le chart de batlehub). Champs `managed` et
`external` optionnels, une règle CEL impose exactement l'un des deux :
pas d'enum Rust taggé (kube-core ne sait pas fusionner son schéma, règle
de forgejo « one-of = struct plate »). Les deux portent le même
`spec.config`.

### 2.8 Une instance namespacée : le `LocalInstance` du kit

L'instance est le kind namespacé `BatleHubLocalInstance` (D2, D5), rôle
`LocalInstance` du kit, comme `ForgejoLocalInstance` et
`AuthentikLocalInstance`. Pas de kind cluster-scoped en v1alpha1 (un
`BatleHubInstance` cluster pourra venir plus tard). Le mode managed
possède ses objets par owner reference.

- `spec.instanceRef` des autres kinds est l'`InstanceRef` du kit
  (`{name, kind?, namespace?}`) et l'instance retenue est enregistrée
  dans `status.instance` (`BoundInstance`), comme dans le gabarit. Sans
  kind cluster, `kind` ne peut valoir que `LocalInstance` ; le laisser
  vide est la forme normale.
- Résolution par les fonctions pures de `weebo_kit_application::instances`
  : chaque `BatleHubLocalInstance` est un `Candidate::local(ns, name,
  None)`, `Candidates.cluster` est vide. `resolve_bound` donne : sans
  `instanceRef`, la seule instance du namespace, puis **celle
  enregistrée tant qu'elle reste candidate** ; `check_binding` refuse
  qu'un même nom désigne une autre instance que celle enregistrée.
- Un `instanceRef.namespace` étranger est refusé (`InstanceNotAllowed`) :
  `BatleHubLocalInstance` n'a pas de `sharedWith` en v1alpha1, hors
  `BatleHubRegistry` (rattachement cross-namespace par consentement de
  l'instance, 4.2).
- Les erreurs neutres du kit (`ResolveError`) sont mappées sur les codes
  du gabarit : `InstanceNotFound` (`NotFound`, `NoInstance`),
  `InstanceAmbiguous` (`Ambiguous`), `InstanceNotAllowed`
  (`NotShared`, `OutsideScope`, `InvalidRef`), `InstanceBindingChanged`
  (`BindingChanged`). L'instance trouvée mais pas encore réconciliée
  (`RefState::NotReconciled` du kit) ou pas `Ready` donne
  `InstanceNotReady`, qui reprend la raison de l'instance dans son
  message.
- Le jeton est lu par `read_local_instance_token` (label
  `batlehub.weebo.io/instance-token: "true"`, `TokenSecretNotAllowed`
  sinon, §2.11), comme le fait la gateway factory du gabarit depuis le
  kit v0.14.2.
- `Instances<I, L>` (adaptateur du kit) exige un kind cluster-scoped `I` :
  l'opérateur implémente le port `InstanceDirectory` sur ses seules
  instances locales (`LocalInstanceDirectory`, ~100 lignes, reflector sur
  `BatleHubLocalInstance` + les fonctions pures ci-dessus). Un
  `Instances` sans kind cluster est proposé au kit (§11.2) ; ce n'est
  **pas** un prérequis du M0/M1.
- Écart au gabarit, fait au M0 : le gabarit génère `BatleHubInstance`
  (cluster) et `BatleHubLocalInstance` (namespacé). M0 supprime le kind
  cluster (CRD, controller, RBAC, docs) et garde le kind namespacé tel
  quel (plural `batlehublocalinstances`, short name `bhli`).

### 2.9 L'opérateur est l'admin qui approuve les reloads

batlehub ne propage pas un reload entre réplicas : chaque processus
surveille son propre fichier monté et, quand les octets changent, stage
un _pending reload_ qu'un admin doit approuver dans les 10 minutes.
L'opérateur est cet admin, sur **chaque pod proxy**, avec son propre
token, en appelant chaque pod par son IP (`http://<podIP>:<port>`),
jamais via le Service (qui en choisirait un au hasard). Protocole : 6.1.

### 2.10 Les refus deviennent un état, pas une boucle d'erreur

Une réponse de l'API admin qui dit « non » est un `Outcome` en échec
(status + Event), pas une `Error` rendue au controller.

**Le sens d'un code HTTP dépend de l'endpoint** (vérifié dans les
annotations utoipa de batlehub 1.4.0) : il n'y a pas de table globale.
Chaque méthode de `HttpAdminGateway` traduit les réponses de son endpoint
en une `GatewayError` neutre (`RemoteError` du gabarit pour l'inattendu),
et le use case la mappe sur un code :

| Endpoint | Réponse | Sens | Raison |
| --- | --- | --- | --- |
| `POST /admin/config/reload`, `…/validate`, `…/from-content`, `…/pending*` | 503 | hot reload désactivé | `HotReloadDisabled` |
| idem | 400 | config refusée | `ConfigRejected` |
| `GET /admin/registries/{r}/…/policy` | 404 | **aucune policy sur ce nœud** : état normal, pas une erreur | — (rien à comparer, la policy est écrite) |
| `DELETE …/policy`, `DELETE …/grants` | 200/204 même absent | idempotent | — |
| `PUT /admin/registries/{r}/grants` | 409 | le sujet détient ces verbes par l'**ownership** | `GrantHeldByOwnership` |
| idem | 400 | action inconnue, sujet illisible, ensemble vide, **ou version inexistante** (le message de batlehub le dit) | `RemoteRejected` |
| grants, policies | 503 | stockage des grants non configuré | `GrantStorageUnavailable` |
| exemptions | 403 | `gates:exempt` manquant (aucun rôle ne l'a, 4.5) | `ExemptionNotPermitted` |
| tous | 401 ; 403 hors exemptions | jeton inconnu ; rôle insuffisant | `OperatorUnauthorized` |
| tous | réseau, timeout, 502/504 | | `InstanceUnreachable` |
| tous | 500 et toute réponse non prévue | | `RemoteError` (le message garde le statut et le début du corps, sans secret) |

**Son objet contre une référence** (leçon A1 d'authentik) : ce que
l'opérateur a écrit et qui a disparu côté batlehub (un grant, une
policy, une exemption effacés à la console) n'est pas une erreur, c'est
une dérive réécrite (4.6). Une référence absente (registry inconnue de
l'instance, version qui n'existe pas) est `RemoteNotFound` ou
`RemoteRejected` : seul un changement de spec ou de l'instance la lève.

**Reprise** : `requeue_after(steady, due_in)` du kit. `steady = true`
(300 s ±20 %) pour les erreurs qu'**un changement de spec seul** peut
lever (`needs_a_change`, comme forgejo et authentik) : `InvalidSpec`,
`ConfigInvalid`, `ConfigRejected` (et son backoff 6.1), `RemoteRejected`,
`OperatorTokenShadowed`, `GrantConflict`, `PolicyConflict`,
`GrantHeldByOwnership`, `ExemptionNotPermitted`, `DuplicateRegistryName`,
`NamespaceNotAllowed`, `InstanceNotAllowed`, `InstanceBindingChanged`,
`InstanceAmbiguous`, `ConfigReadOnly`, `RestartForbidden`,
`InstanceConfigUnmanaged`, `OwnedObjectConflict`, `SecretNotAllowed`,
`TokenSecretNotAllowed`. Chacune est de toute façon relancée tout de
suite par le changement qui la lève (prédicats du kit, watches 6.7).
Les autres (`InstanceUnreachable`, `OperatorUnauthorized`,
`TokenSecretMissing`, `InstanceNotFound`, `InstanceNotReady`,
`RemoteError`, `GrantStorageUnavailable`…) reprennent à 30 s ;
`ConfigPropagating` à 15 s (`due_in`).

Seules les erreurs Kubernetes de l'opérateur lui-même (lecture, apply,
patch de status, finalizer) remontent en `Error` : `KubernetesApiError`,
Event `Warning` et reprise ~30 s par `retry_after_error`.

### 2.11 Secrets envoyés ailleurs : opt-in par label

L'opérateur lit les Secrets avec **ses** droits, et un CR namespacé peut
lui faire envoyer leur contenu à une URL qu'il choisit (le token admin
d'une instance external, les couches poussées par `manageConfig`) ou dans
la config d'une instance d'un autre namespace (`configFrom` d'une
registry rattachée). Quiconque peut créer ces CR ferait sortir n'importe
quel Secret de son namespace sans pouvoir le lire lui-même : la faille
corrigée dans le kit v0.14 (K16) et dans forgejo
(`forgejo.weebo.io/credential`). Règle de la v2 :

- **Token d'une instance** (`external.adminTokenSecretRef`,
  `managed.operatorAccess.tokenSecretRef`) : lu par
  `weebo_kit_adapters::read_local_instance_token`, qui exige le label
  `batlehub.weebo.io/instance-token: "true"` (`annotations::INSTANCE_TOKEN`
  du kit) ; `TokenSecretError::NotAllowed` → `TokenSecretNotAllowed`,
  `Missing` → `TokenSecretMissing`. Le contenu d'un Secret non labellisé
  n'est jamais lu.
- **Tout autre Secret dont le contenu part chez batlehub** (Secrets de
  `configLayers`, `credentials`, `configFrom` d'une registry) : label
  `batlehub.weebo.io/credential: "true"`, sinon `SecretNotAllowed` (le
  message nomme le Secret et la commande `kubectl label`). Les ConfigMaps
  n'en ont pas besoin.
- **Hors règle** : les `env[].valueFrom.secretKeyRef` d'une instance
  managed sont montés par le kubelet, pas par l'opérateur ; leur valeur
  n'est lue que pour valider (2.6) et n'est ni rendue ni envoyée.
- **CA** : `external.tls` lit son `caSecretRef` dans le namespace de
  l'instance (type `LocalTlsOptions` du kit, dont le nom n'apparaît pas
  dans le schéma), jamais un `TlsOptions` qui porte un `SecretKeyRef`
  cross-namespace.
- Les Secrets écrits par l'opérateur (`<name>-config`,
  `<name>-operator-token`, `<name>-operator-auth`) portent eux-mêmes les
  labels, puisqu'il les relit.

## 3. Architecture et conventions

### 3.1 Workspace

Généré par le gabarit du kit
(`cargo generate --git https://github.com/batleforc/weebo-operator-kit --tag v0.14.2 templates/operator`,
`product = BatleHub`), rendu hors de tout workspace. v0.14.2 est la
première version dont le gabarit lit le token d'une instance namespacée
par `read_local_instance_token` (opt-in du label, 2.11) ; un rendu d'un
tag antérieur hériterait de `read_secret_key` sans contrôle. Puis :

| Crate | Contenu propre à batlehub |
| --- | --- |
| `domain` | `ReasonCode` (§5), hashs (config, redémarrage, policy), plan de rollout et de maintenance, cron, décision de rattachement des registries, comparaison des grants. Aucune dépendance hors kit. |
| `api` | Les 5 CRD, `GROUP`, `ANNOTATIONS` (kit) + annotations propres, table des actions de maintenance (source des règles CEL). |
| `application` | Ports : `AdminGateway` (+ factory par instance / par pod), `ConfigParser`, `WorkloadStore` (lecture des pods, apply des objets possédés), `ClusterReader` (Secrets/ConfigMaps/Namespaces/registries). Use cases `reconcile_instance`, `reconcile_registry`, `reconcile_maintenance`, `reconcile_package_grant`, `reconcile_package_policy`, rendu de config. `test_support` : `FakeBatleHub`, `FakeWorkload`. |
| `batlehub-client` | **Généré** (openapi-generator) depuis `spec/batlehub-v1.4.0.json` + `spec/patches/*.jq` ; `task gen:client`. |
| `adapters-outbound` | `HttpAdminGateway` sur `batlehub-client` (mapping par endpoint, 2.10), `BatleHubConfigParser` sur `merge_layers`/`validate_layers`, `KubeWorkloadStore` (SSA), `KubeClusterReader` (lecture des Secrets par les helpers à opt-in du kit, 2.11), `LocalInstanceDirectory` (port `InstanceDirectory`, 2.8), hash Argon2id du token. |
| `adapters-inbound` | Un controller par kind sur le squelette du kit, admission (`Admission`), métriques propres. |
| `operator` | Le binaire (kit : télémétrie, leader election, webhook, `Shutdown`). |
| `crdgen`, `testkit` | Ceux du gabarit (envtest, `StaticGatewayFactory`). Le kind cluster généré par le gabarit est supprimé, le kind namespacé `BatleHubLocalInstance` gardé (2.8). |
| `importer` (M5) | `weebo-batlehub-importer` : release Helm de batlehub → `BatleHubLocalInstance` ; grants/policies d'une instance → CR en pause (`Adopter` du kit). |

`api` et `batlehub-client` restent réutilisables par un plugin kubectl ou
par la CLI batlehub sans tirer le contrôleur.

Règle des adaptateurs entrants (forgejo) : aucune lecture cluster hors du
CR réconcilié, tout passe par les ports.

### 3.2 Noms

| Quoi | Valeur |
| --- | --- |
| Repo / chart / image | `weebo-batlehub`, `ghcr.io/batleforc/weebo-batlehub` |
| Groupe / version | `batlehub.weebo.io/v1alpha1` |
| Kinds (short names) | `BatleHubLocalInstance` (`bhli`), `BatleHubRegistry` (`bhr`), `BatleHubMaintenance` (`bhm`), `BatleHubPackageGrant` (`bhpg`), `BatleHubPackagePolicy` (`bhpp`) |
| Field manager, reporter d'Events | `weebo-batlehub-operator` |
| Finalizer | `batlehub.weebo.io/finalizer` |
| Préfixe des métriques | `weebo_batlehub` |
| Lease | `weebo-batlehub-operator-leader` (chart du kit) |
| Identité batlehub de l'opérateur | `user_id = weebo-batlehub-operator` |

### 3.3 Annotations

Celles du kit (`Annotations::new("batlehub.weebo.io")`), même sens que
partout :

- `force-orphan` : libère le finalizer sans révoquer (instance déjà
  partie) ;
- `import-pending` : posée par l'importeur, le controller laisse le CR ;
- `allow-disruptive-update` : autorise un changement que l'opérateur ne
  peut appliquer qu'en détruisant (changement de `server.port` sous
  `reload.restart: Never` forcé, passage d'un stockage RWO en `Recreate`
  sur une instance à plusieurs réplicas…).

Propres à batlehub, dans `api` :

- `batlehub.weebo.io/config-hash` : sur le pod template, le hash de
  redémarrage ;
- `batlehub.weebo.io/approved-config-hash` : approbation d'une config
  retenue par `reload.strategy: Manual` ;
- `batlehub.weebo.io/run-now` : sur une maintenance planifiée, déclenche
  un run immédiat quand sa valeur change (le prédicat d'annotations du
  kit déclenche le reconcile).

## 4. Les CRD (`batlehub.weebo.io/v1alpha1`)

Status commun à tous les kinds : `observedGeneration`, `conditions`
(type `Condition` du kit : `Ready` + advisories), puis les champs propres
listés par kind. Les kinds qui visent une instance portent en plus
`instance` (`BoundInstance` du kit, 2.8). Colonnes kubectl communes :
`READY`, `REASON`, `AGE`.

Tout ce que l'opérateur crée ou écrit côté batlehub est enregistré dans
le status **dès que l'écriture a réussi**, même si une étape suivante de
la même passe échoue (leçon F6 de forgejo, A3/A5 d'authentik) ; avant de
juger qu'un objet distant est étranger (conflit), le status est **relu
depuis l'apiserver**, pas depuis le cache du watch.

### 4.1 BatleHubLocalInstance (`bhli`)

**spec, champs communs aux deux modes**

| Champ | Défaut | Rôle |
| --- | --- | --- |
| `config` | | Le TOML batlehub en YAML. Clés inconnues conservées. |
| `configLayers[]` | | `{configMapRef\|secretRef: {name, key}}`, fusionnées dans l'ordre par-dessus `config`. Clé par défaut `config.toml`. Un Secret doit porter `batlehub.weebo.io/credential: "true"` (2.11). |
| `credentials` | | `{name, key}` d'un Secret du namespace de l'instance contenant une couche `credentials.toml`, labellisé `credential` (2.11). Voir 6.4. |
| `reload.strategy` | `Auto` | `Manual` retient une config validée jusqu'à l'approbation de son hash exact. |
| `reload.restart` | `Rollout` | `Never` : un changement de clé à redémarrage lève l'advisory `RestartRequired` au lieu de rouler les pods. |
| `reload.validation` | `Strict` | `Lenient` applique une config que le parser refuse (cas où c'est une valeur factice de placeholder qui échoue). |
| `registrySelector.selector` | | Sélecteur de labels sur les `BatleHubRegistry`. |
| `registrySelector.namespaces.from` | `Same` | `Same`, `All` ou `Selector` (modèle de `allowedRoutes.namespaces` de la Gateway API). |
| `registrySelector.namespaces.selector` | | Sélecteur sur les labels des Namespaces, obligatoire avec `Selector` (CEL). |

Pas de `suspend` : la pause est l'annotation `import-pending` du kit pour
l'importeur ; un `suspend` propre n'est ajouté que si un besoin réel
apparaît (un champ de moins dans tous les kinds).

**spec.managed** : les valeurs par défaut reprennent celles du chart Helm
de batlehub, pour qu'un `values.yaml` se traduise ligne à ligne (§8).

| Champ | Défaut | Rôle |
| --- | --- | --- |
| `image.repository` / `tag` / `pullPolicy` | `ghcr.io/batlehub/batlehub` / version ciblée par l'opérateur (`WEEBO_BATLEHUB_DEFAULT_IMAGE`) / `IfNotPresent` | |
| `imagePullSecrets[]` | | |
| `replicas` | 1 | Un stockage filesystem sur volume RWO plafonne à 1. |
| `updateStrategy` | dérivé | Voir 6.2. |
| `resources` | | |
| `service.type` / `port` / `annotations` | `ClusterIP` / 8080 | Le port du conteneur suit toujours `config.server.port`. |
| `ingress.host` / `extraHosts[]` / `className` / `annotations` / `tls[]` | | Une règle par host. Les hosts ne sont **pas** dérivés de `registries[].hosts` : `server.trusted_proxies` doit être réglé en conscience. |
| `persistence.enabled` / `size` / `storageClass` / `accessMode` / `existingClaim` / `ephemeralSizeLimit` | true / 10Gi / défaut / RWO / / 1Gi | PVC du cache d'artefacts, seulement quand le stockage par défaut est filesystem. |
| `worker` | absent | Deployment séparé `--roles worker` ; le proxy passe alors en `--roles proxy`. Champs : `replicas`, `image`, `resources`, `runtimeClassName` (gVisor), `scratchSizeLimit` (4Gi), `nodeSelector`, `tolerations`, `autoscaling{minReplicas, maxReplicas, targetQueued, metricName}` (HPA sur la profondeur de file). Avec un stockage filesystem, le worker monte le cache du proxy ; si le volume n'est pas RWX, une pod affinity obligatoire sur `kubernetes.io/hostname` le place à côté d'un pod proxy. `TMPDIR=/tmp/batlehub`. |
| `podDisruptionBudget.minAvailable` / `maxUnavailable` | | Rendu seulement à partir de 2 réplicas. |
| `networkPolicy.ingressFrom[]` / `egressTo[]` | | Sur les pods proxy et worker. Ingress sur le port HTTP ; `ingressFrom` vide = toute source ; non vide, l'opérateur y ajoute ses propres pods pour garder l'accès à l'API admin. Egress refusé par défaut sauf DNS. |
| `serviceAccount.create` / `name` / `annotations` / `autoTokenReview` | true / nom de l'instance / / true | `autoTokenReview` lie TokenReview quand un provider d'auth `kubernetes` est configuré ; `automountServiceAccountToken` n'est activé que dans ce cas. |
| `operatorAccess.generateToken` / `tokenSecretRef` / `userId` | true / / `weebo-batlehub-operator` | Voir 6.3. Un `tokenSecretRef` fourni doit porter le label `instance-token` (2.11). |
| `hotReload` | true | `false` pose `BATLEHUB_DISABLE_HOT_RELOAD=1` : tout changement devient un redémarrage. |
| `env[]` / `envFrom[]` | | Environnement des deux conteneurs ; source des `${VAR}`. |
| `podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`, `runtimeClassName` | | Scheduling. |
| `extraVolumes[]` / `extraVolumeMounts[]` | | CA bundles, `static_dir`, `cli_binary_path`. |
| `podSecurityContext` / `securityContext` | non-root 65532, seccomp `RuntimeDefault` / rootfs en lecture seule, aucune capability, pas d'escalade | |

**spec.external**

| Champ | Défaut | Rôle |
| --- | --- | --- |
| `url` | requis | URL de base. |
| `adminTokenSecretRef` | requis | `{name, key}` d'un Secret du namespace de l'instance portant un token admin, labellisé `batlehub.weebo.io/instance-token: "true"` et lu par `read_local_instance_token` (2.11). Relu à chaque reconcile : une rotation ne demande pas de redémarrage. |
| `tls` | | `caSecretRef` (Secret du namespace de l'instance), `insecureSkipVerify`. |
| `podSelector` | | Sélecteur des pods proxy de l'instance quand elle tourne dans le cluster (chart batlehub) : l'opérateur approuve alors pod par pod comme en managed (6.6). Absent : un seul point d'entrée, `url`. |
| `manageConfig` | false | Pousse `spec.config` via l'API admin. Sinon, observation et maintenance seulement. |

**status (champs propres)**

| Champ | Rôle |
| --- | --- |
| `configHash` | SHA-256 du fichier rendu (config désirée). |
| `appliedConfigHash` | Config confirmée sur chaque pod proxy. |
| `pendingConfigHash` | Config retenue par `Manual`. |
| `credentialsHash` | SHA-256 de la couche `credentials`. |
| `reloadNonce` | Voir 6.1. |
| `rejectedConfigHash` / `lastRejectionTime` | Dernière config refusée par l'instance, et quand. |
| `updateStrategy` | Stratégie effective du Deployment proxy. |
| `restartKeys[]` | Clés à redémarrage changées, tant qu'un redémarrage est en attente. |
| `pods[]` | `{name, configHash}` des pods proxy en retard (vide une fois appliqué). |
| `version` | Version batlehub lue sur `/livez`. |
| `endpoint` | URL utilisée par l'opérateur. |
| `warnings[]` | `{code, path, message}` de `GET /admin/config/warnings`. |
| `lastReloadTime`, `availableReplicas` | |

`Ready: True` = l'instance répond, le token de l'opérateur est accepté
**avec le rôle admin** et elle tourne la config désirée (ou
`manageConfig` est off). `/livez` n'est pas authentifié : le token est
vérifié par `GET /api/v1/me` (`MeResponse.role`), un rôle autre
qu'`admin` donne `OperatorUnauthorized` (le message dit le rôle reçu).
Raisons et advisories : §5.

**Finalizer** (dès le M1) : `batlehub.weebo.io/finalizer`. Tant qu'un
CR est lié à l'instance (`status.instance`, ou `instanceRef` le nomme),
la suppression attend : `Ready: False`, `InstanceInUse`, le message
nomme les CR liés ; `force-orphan` sur l'instance la libère et laisse
ces CR (et ce qu'ils ont écrit côté batlehub) orphelins. C'est le modèle
de forgejo et d'authentik : sans lui, supprimer l'instance laisse tous
les grants et policies sur le serveur sans plus personne pour les
révoquer.

**Colonnes kubectl** : `ENDPOINT`, `VERSION`, `READY`, `REASON`, `AGE`.

### 4.2 BatleHubRegistry (`bhr`)

Une entrée `[[registries]]` sous forme d'objet séparé, pour que chaque
équipe gère ses registries.

**spec**

| Champ | Défaut | Rôle |
| --- | --- | --- |
| `instanceRef` | seule instance du namespace | `InstanceRef` du kit (2.8) : le `BatleHubLocalInstance` visé, éventuellement d'un autre namespace (rattachement ci-dessous). |
| `type` | requis | `npm`, `cargo`, `pypi`, … validé par le parser. |
| `name` | nom de l'objet | Nom servi par batlehub. |
| `config` | `{}` | Toutes les autres clés de la table (`mode`, `upstreams`, `rbac`, `rules`, `cache`, `retention`, `quota`, `rate_limit`, `hosts`, `namespaces`, …). |
| `configFrom[]` | | Fragments TOML depuis ConfigMaps/Secrets (`upstream_auth`, `tls`, graines de signature), lus **dans le namespace de la registry** ; un Secret doit porter `batlehub.weebo.io/credential: "true"` (2.11, sinon `SecretNotAllowed`). Un fragment ne peut pas changer `type` ni `name`. |
| `suspend` | false | Garde l'objet, exclut la registry. |

**Rendu**

- C'est le **contrôleur d'instance** qui rend les registries : un watch
  sur le kind ramène chaque changement à l'instance, qui ajoute une
  couche TOML contenant toutes les registries acceptées, triées par
  namespace puis nom, fusionnée après `configLayers`.
- Une registry dont le `name` correspond à une entrée statique de
  `spec.config.registries` la complète au lieu de la dupliquer (registry
  du namespace de l'instance seulement, voir plus bas).
- **Deux `BatleHubRegistry` rattachées à la même instance avec le même
  `name`** ne sont jamais fusionnées (la fusion par `name` de 2.3 le
  ferait en silence) : la plus ancienne (`creationTimestamp`, puis
  namespace/nom) est rendue, les autres passent en `Ready: False`,
  `DuplicateRegistryName`, le message nomme celle qui est rendue. Le
  webhook refuse aussi un doublon visible à l'admission (même
  `instanceRef` résolu, même `name`) ; ce qu'il ne voit pas (rattachement
  par sélecteur) est tranché au rendu.
- Instance **external sans `manageConfig`** : l'opérateur ne rend rien,
  une registry ne peut pas y être appliquée : `Ready: False`,
  `InstanceConfigUnmanaged` (pas de refus au webhook : `manageConfig` peut
  être activé ensuite).
- Un changement déclenche toujours un hot-reload (les registries ne sont
  jamais une clé à redémarrage).
- Le contrôleur d'instance écrit ensuite le status de chaque registry
  (`status::publish` du kit). Le contrôleur `registry` ne traite que ce
  que l'instance ne rend jamais : instance absente ou namespace refusé.

**Rattachement cross-namespace**

- Le namespace de l'instance est toujours admis ; les autres seulement
  selon `registrySelector.namespaces`. C'est le consentement du
  propriétaire de l'instance (modèle Gateway API), pas une allow-list
  d'administrateur : pas de `BatleHubNamespacePolicy` en v1alpha1, les
  autres kinds ne sortent pas de leur namespace.
- Ce consentement passe par la résolution du kit (2.8) : pour une
  registry, la `Candidate` de l'instance porte un `SharedWith` dérivé de
  `registrySelector.namespaces` (`Same` : aucun, `All` : sélecteur vide,
  `Selector` : `namespaceSelector`), et `resolve_bound` rend
  `InstanceNotAllowed` hors consentement. Les autres kinds résolvent sans
  `SharedWith`. La même fonction pure (`domain`) dérive ce `SharedWith`
  pour l'instance (en listant les candidates) et pour le contrôleur
  registry (pour expliquer le refus).
- Opérateur limité à un namespace (`watch.namespace`, D6) : pas de
  rattachement cross-namespace, `from: All`/`Selector` donnent
  l'advisory `RegistrySelectorIgnored` sur l'instance et les registries
  d'ailleurs ne sont pas vues.
- En mode cluster, l'opérateur surveille les Namespaces et ré-rend les
  instances en mode `Selector` dès qu'un label change.
- Une registry d'un autre namespace :
  - ne peut contenir `${` nulle part : batlehub résout les placeholders
    depuis l'environnement de l'instance, ce qui donnerait son mot de
    passe de base ou ses clés S3 à quiconque écrit la registry ;
  - ne peut pas compléter une registry déclarée dans la config de
    l'instance (`DuplicateRegistryName`).

**status** : `registryName`, `instance` (`BoundInstance`),
`instanceConfigHash` ; raisons de `Ready` : `Reconciled` (rattachée),
`RegistrySuspended` (advisory), `ConfigInvalid` (rendu refusé),
`DuplicateRegistryName`, `InstanceRejected` (l'instance refuse sa
config), `InstanceConfigUnmanaged`, `NamespaceNotAllowed` (`${` d'un
autre namespace), `SecretNotAllowed`, `ConfigLayerMissing` (fragment
absent), `InstanceNotFound`, `InstanceAmbiguous`, `InstanceNotAllowed`,
`InstanceBindingChanged`, `InstanceNotReady`.

### 4.3 BatleHubMaintenance (`bhm`)

Une action administrative contre une instance, unique ou planifiée.

**spec**

| Champ | Défaut | Rôle |
| --- | --- | --- |
| `instanceRef` | seule instance du namespace | `InstanceRef` du kit, même namespace (2.8). |
| `action` | requis | Voir le catalogue. |
| `params` | `{}` | `registry`, `package`, `version`, `artifact`, `path`, `packages[]`, `paths[]`, `versions`, `dryRun`, `ip`, `user`, `reason`, `durationSeconds`, `before`, `olderThanDays`, `state`, `tag`, `repo`, `message`, `level`. |
| `schedule` | | Cron à 5 champs, UTC, jour de semaine 0-7 depuis dimanche. Absent : exécution unique. |
| `suspend` | false | Met en pause une planification. |
| `ttlSecondsAfterFinished` | | Supprime une exécution unique terminée après ce délai. |
| `timeoutSeconds` | 600 | Borne le run et la requête. |

**Comportement**

- Pas de CronJob ni de pod : l'opérateur est l'ordonnanceur. Il calcule le
  prochain déclenchement depuis le dernier run et se remet en file pour
  l'heure exacte (`requeue_after(_, Some(due_in))` du kit : l'échéance
  n'est pas soumise à la gigue).
- `params.dryRun` vaut **true par défaut** : un flag omis rapporte sans
  rien changer.
- **Au plus une fois** : la décision de lancer est prise sur l'objet
  relu depuis l'apiserver (pas le cache), et `status.lastRun.state:
  Running` est écrit **avant** l'action, par un patch de status
  **conditionné par le `resourceVersion` relu** (le patch de status du
  kit ne l'est pas : l'opérateur fait le sien pour cette seule écriture).
  Un conflit (409) veut dire qu'un autre a écrit entre-temps : on ne
  lance pas, la passe suivante relit. Un reconcile qui trouve `Running`
  (opérateur arrêté en cours de run) le clôt en `Failed`
  (`MaintenanceInterrupted`) au lieu de le rejouer : des actions comme
  `restart` ou `releaseImport` ne doivent pas tourner deux fois dans le
  dos de l'utilisateur.
- `status.lastRun.result` contient la réponse brute de l'instance,
  remplacée par un résumé au-delà de 32 KiB ; `status.lastRun.message`
  résume les champs scalaires de la réponse ou l'erreur.
- Les params obligatoires de chaque action sont vérifiés par une règle
  CEL par action, générée depuis une table unique (`api`), et revérifiés
  au run.

**status (champs propres)** : `lastRun{state (Running, Succeeded,
Failed), startTime, completionTime, message, result}`, `nextRunTime`,
`runCount`, `failureCount`. Remplace la `phase` de la v0.1 : l'état du
run est une donnée, `Ready` en est le résumé — `True` (`Reconciled`) quand
le dernier run a réussi ou que la planification est armée, `False` sur
`MaintenanceFailed`, `MaintenanceTimeout`, `MaintenanceInterrupted`,
les erreurs d'instance de 2.8 (`InstanceNotFound`, `InstanceAmbiguous`,
`InstanceNotAllowed`, `InstanceBindingChanged`, `InstanceNotReady`) ;
advisories `MaintenanceRunning`, `MaintenanceSuspended`.

**Colonnes kubectl** : `INSTANCE`, `ACTION`, `SCHEDULE`, `LAST RUN`
(`.status.lastRun.state`), `RUNS`, `NEXT`, `READY`.

**Catalogue des actions** (chemins relatifs à `/api/v1` ; « dryRun » =
l'action respecte `params.dryRun`)

| Action | Endpoint | Params |
| --- | --- | --- |
| `configReload` | `POST /admin/config/reload` sur chaque pod proxy ; ou approbation d'une config retenue (voir 6.1) | |
| `configValidate` | `POST /admin/config/validate` avec la config rendue | |
| `configApplyPending` | `POST /admin/config/pending/apply` — **instance external sans `manageConfig` seulement** (refusé ailleurs : `InvalidSpec`) ; ailleurs, le protocole 6.1 décide seul de ce qu'il approuve et `appliedConfigHash` resterait faux | |
| `configDiscardPending` | `DELETE /admin/config/pending` | |
| `cacheWarm` | `POST /admin/registries/{registry}/warm` | `registry`, `packages[]`/`package`, `paths[]`/`path`, `versions` |
| `cacheClearMetadata` | `POST /admin/registries/{registry}/clear-cache` | `registry` |
| `cacheClearArtifacts` | `DELETE /admin/registries/{registry}/cache` | `registry` ; `package`, `version`, `path` restreignent |
| `cacheEvict` | `POST /admin/registries/{registry}/evict?dry_run=` | `registry`, dryRun |
| `cacheCoherence` | `POST /admin/registries/{registry}/coherence?dry_run=` | `registry`, dryRun (deux passes : marque puis supprime, à planifier) |
| `packageInvalidate` | `POST /admin/packages/invalidate` | `registry`, `package`, `version`, `artifact` |
| `exploreInvalidate` | `POST /admin/explore/invalidate` | `registry` (optionnel) |
| `retentionRun` | `POST /admin/registries/{registry}/retention?dry_run=` | `registry`, dryRun (récupère seulement si dryRun=false **et** `retention.dry_run=false` côté registry) |
| `tombstonesCompact` | `POST /admin/registries/{registry}/tombstones/compact?dry_run=` | `registry`, dryRun |
| `vulnerabilityRescan` | `POST /admin/verdicts/rescan` | `registry`, `state` |
| `verdictBackfill` | `POST /admin/verdicts/backfill` | `registry`, `state` |
| `upstreamRecheck` | `POST /admin/upstream/recheck` | `registry`, `package`, `version` |
| `auditLogPurge` | `DELETE /admin/audit-log?before=` | `before` (RFC 3339) ou `olderThanDays` |
| `airGapMissingPurge` | `DELETE /admin/air-gap/missing` | `before`/`olderThanDays`, `registry`, optionnels |
| `releaseImport` | `POST /admin/registries/{registry}/import` | `registry`, `tag`, `repo` |
| `ipBlock` | `POST /admin/ip-blocks` | `ip`, `reason`, `durationSeconds` |
| `ipUnblock` | `DELETE /admin/ip-blocks/{ip}` | `ip` |
| `userBlock` | `POST /admin/users/{user}/block` | `user`, `reason` |
| `userUnblock` | `DELETE /admin/users/{user}/block` | `user` |
| `packageBlock` | `POST /admin/packages/block` | `registry`, `package`, `version`, `reason`, `artifact` |
| `packageUnblock` | `POST /admin/packages/unblock` | `registry`, `package`, `version`, `artifact` |
| `quotaReset` | `DELETE /admin/quota/{registry}/{user}` | `registry`, `user` |
| `bannerSet` | `PUT /admin/banner` | `message`, `level` (`info`, `warning`, `error`) |
| `bannerClear` | `DELETE /admin/banner` | |
| `restart` | Côté opérateur : redémarrage progressif des Deployments proxy et worker (managed seulement, livré au M4) | |
| `healthCheck` | Côté opérateur : `GET /healthz` + `GET /admin/health`, les deux dans `lastRun.result` | |

Sur une instance managed (ou external avec `podSelector`), `configReload`
va à chaque pod proxy ; `lastRun.result.pods` dit, par pod, s'il a
rechargé ou n'avait rien de nouveau. Sur une instance qui retient une
config (`Manual`), il n'appelle pas l'instance : il pose l'annotation
`batlehub.weebo.io/approved-config-hash` avec le hash retenu.

**Volontairement hors catalogue**

- Grants, policies et exemptions : c'est de l'état, porté par
  `BatleHubPackageGrant` et `BatleHubPackagePolicy`.
- Clés de signature, notifications : travail d'admin courant avec son UI
  et ses verbes CLI.
- Backup/restore : aucun endpoint. L'import de bundle air-gap demande un
  upload de fichier, un CRD n'est pas le bon véhicule.
- Pin de rétention, export d'exposition, export d'audit : lectures ou
  opérations par paquet.

### 4.4 BatleHubPackageGrant (`bhpg`)

Les grants d'un paquet ou d'une version d'une registry : les niveaux
package et version du modèle d'accès de batlehub, qui vivent dans sa base
et non dans sa config (les niveaux instance et registry sont dans
`spec.config` : `grants`, `registries[].grants`).

**spec**

| Champ | Défaut | Rôle |
| --- | --- | --- |
| `instanceRef` | seule instance du namespace | `InstanceRef` du kit, même namespace (2.8). |
| `registry` | requis | Nom de registry, ≤ 253 caractères. |
| `package` | requis | ex. `@acme/billing`, ≤ 1024 caractères. |
| `version` | | Une version, ≤ 256 caractères ; absente = le nœud du paquet. |
| `grants[]` | requis | `{subject, actions[]}`, une entrée par `subject` (clé de list-map). Sujets en orthographe batlehub : `user:alice`, `group:oidc1:eng`, `role:user`, `*`. Actions = motifs, `releases:*` compris. |
| `deletionPolicy` | `Delete` | `Delete` révoque à la suppression ; `Orphan` laisse en place (ex-`Retain`). Type défini dans l'`api` de l'opérateur, sur le modèle de forgejo (`api/src/common.rs`) : le kit n'en fournit pas. |

Les quatre champs de coordonnée (`instanceRef`, `registry`, `package`,
`version`) sont **immuables** (règle CEL de transition) et ne peuvent être
ni vides, ni `.`, ni `..` : le status mémorise ce qui a été écrit à cette
coordonnée, la déplacer laisserait des lignes orphelines.

Écriture : `PUT /admin/registries/{registry}/grants`, un sujet à la fois.
Le token opérateur porte le rôle admin, qui inclut `grants:*`.

**Échec partiel** : `status.applied[]` est patché **après chaque
écriture réussie**, pas en fin de passe. Sinon, sujet 1 écrit, sujet 2
en échec, status non patché : à la passe suivante, le sujet 1 paraît
étranger et le CR se met en `GrantConflict` sur son propre grant. Avant
de conclure à un conflit, le status est relu depuis l'apiserver. Même
règle pour `appliedPolicyHash`/`observedPolicyHash` et
`appliedExemptions[]` (4.5).

**status (champs propres)** : `applied[]` (`{subject, requested[],
stored[]}` : ce qui a été écrit, et l'ensemble étendu que batlehub a
stocké — il étend `releases:*` à l'écriture), `warnings[]` (grants légaux
mais probablement involontaires), `lastSyncTime`. Raisons de `Ready` :
`Reconciled`, `GrantConflict`, `GrantHeldByOwnership` (409 : le sujet a
ces verbes par l'ownership, 2.10), `OperatorUnauthorized`,
`RemoteRejected` (400, dont version inexistante), `RemoteNotFound`
(registry inconnue de l'instance), `RemoteError`,
`GrantStorageUnavailable`, `InstanceUnreachable`, les erreurs d'instance
de 2.8 (`InstanceNotFound`, `InstanceAmbiguous`, `InstanceNotAllowed`,
`InstanceBindingChanged`, `InstanceNotReady`) ; advisory
`SuspiciousGrant` pour les `warnings[]`.

### 4.5 BatleHubPackagePolicy (`bhpp`)

La policy d'un paquet ou d'une version, et les exemptions de gates d'une
version.

**spec** : même coordonnée immuable que `BatleHubPackageGrant`, plus :

| Champ | Rôle |
| --- | --- |
| `policy` | Le `PolicyDto` de batlehub en objet ouvert, clés snake_case : `visibility`, `prerelease_visibility`, `quota`, `versioning`, `rules[]` (`{gate, settings}`). Une clé omise hérite du niveau supérieur. Remplace la policy du nœud. |
| `exemptions[]` | `{gate, exemptUntil, reason}`, une par gate (`cve_gate`, `license_gate`, `security_verdict`, `flags`). Date RFC 3339, dans le futur à l'écriture. Exige `version` (CEL). |
| `deletionPolicy` | Comme `BatleHubPackageGrant`. |

Au moins un de `policy` et `exemptions` (CEL). Un gate ne peut pas être à
la fois réglé dans `policy.rules` et exempté (`InvalidSpec`, refusé par le
webhook) : le nœud version porte une seule entrée par gate.

batlehub n'accorde `gates:exempt` à personne, rôle admin compris : les
exemptions demandent un grant à l'identité de l'opérateur
(`user:weebo-batlehub-operator` par défaut) sur la version ou son paquet,
via `config.grants` ou un `BatleHubPackageGrant`. Sans lui, le 403 de
l'endpoint d'exemption donne `ExemptionNotPermitted` (le message donne le
grant à poser), pas un `OperatorUnauthorized` générique.

Lecture : un `GET` de policy qui répond 404 veut dire « aucune policy
sur ce nœud » (état normal : rien en place, l'opérateur écrit la
sienne), pas `RemoteNotFound`.

**status (champs propres)** : `appliedPolicyHash` (hash de `spec.policy`
à l'écriture), `observedPolicyHash` (hash de ce que l'instance a renvoyé
juste après, exemptions exclues), `appliedExemptions[]`, `lastSyncTime`.
`Ready` : raisons de `BatleHubPackageGrant` (sauf `GrantConflict` et
`GrantHeldByOwnership`) + `InvalidSpec`, `PolicyConflict`,
`ExemptionNotPermitted` ; advisory `ExemptionExpired` (le message liste
les exemptions expirées).

### 4.6 Règles communes aux deux kinds de gouvernance

- **L'objet est la source de vérité de ce qu'il liste, et de rien
  d'autre.** Ce qui sort de la spec est retiré parce que le status dit que
  l'opérateur l'avait écrit. Une ligne écrite par la console, la CLI ou
  l'ownership n'est jamais touchée.
- **Collision → rejet, jamais d'adoption implicite** (règle de forgejo) :
  - un sujet dont le nœud porte déjà un grant que le status de ce CR ne
    connaît pas n'est pas écrasé : `Ready: False`, `GrantConflict`, le
    message dit ce qui est en place ; idem pour une policy existante non
    écrite par ce CR (`PolicyConflict`) ;
  - deux CR sur la même coordonnée et le même sujet (grant) ou la même
    coordonnée (policy) : refusé par le webhook, et le second en
    réconciliation reste en conflit ;
  - **seul chemin d'adoption** : l'importeur, qui crée le CR en pause
    (`import-pending`) avec le status amorcé (`applied[]`,
    `appliedPolicyHash`), puis le relâche (`Adopter` du kit).
- **Dérive** : à chaque passe, relecture des lignes et réécriture de ce
  qui a dérivé ; remise en file par le `requeue_after` du kit (300 s ±20 %
  en régime stable). Cette relecture est la détection de dérive : pas de
  watch sur l'instance.
- **Pas de boucle d'écriture** : le status n'est plus un déclencheur
  (prédicats du kit). Si quelque chose défait l'écriture en boucle, cela
  fait une écriture par période de requeue, pas une par event.
  `lastSyncTime` = dernière passe ayant changé quelque chose sur
  l'instance.
- **Grants** : comparés sur le nœud nommé, actions demandées vs dernière
  demande, ensemble stocké vs ensemble stocké renvoyé alors.
- **Policies** : impossible de comparer champ par champ sans reprendre le
  schéma (la lecture remplit les défauts). Juste après l'écriture,
  l'opérateur relit et garde le hash ; une lecture ultérieure qui hashe
  différemment = modifiée ailleurs, réécrite.
- **Exemptions** : batlehub les stocke comme entrées de `rules` de la
  policy de version, avec `exempt: true`. Elles sont lues de là (une seule
  lecture du nœud version), exclues du hash de policy, et reportées quand
  la policy est réécrite (un `PUT` remplace le nœud) ou effacée (un
  `DELETE` les supprimerait). Une exemption expirée est signalée, pas
  réécrite (batlehub refuse une date passée).
- **Suppression** : `finalize` du kit — révocation de ce que l'objet a
  écrit, sauf `deletionPolicy: Orphan` ou `force-orphan`, puis Event
  `Released`. Si l'instance existe mais que son token est illisible, le
  finalizer reste (Event `Warning`, `force-orphan` pour sortir). Une
  instance ne peut pas partir avant ses CR liés (`InstanceInUse`, 4.1) :
  la révocation trouve toujours une instance à qui parler. Instance déjà
  absente (supprimée avec `force-orphan`) : le finalizer est libéré, Event
  `Warning` qui dit que rien n'a été révoqué.

## 5. Codes de raison

Un seul `domain::error::ReasonCode` (`reason_codes!` du kit), PascalCase,
avec sa sévérité. Les doc comments de l'enum deviennent la page
« Reason codes » de la doc (générée par `@weebo/operator-docs`) : chaque
variante dit quand elle apparaît et quoi faire.

La colonne « Steady » marque les codes que seul un changement de spec
lève (`needs_a_change`, reprise à 300 s, 2.10).

| Code | Sévérité | Steady | Où |
| --- | --- | --- | --- |
| `Reconciled` | succès | | `Ready: True`, tous les kinds |
| `InvalidSpec` | bloquant | oui | spec incohérente que seul un changement du CR corrige (CEL contournée, gate réglé et exempté, `configApplyPending` hors external non géré…) |
| `InstanceNotFound` | bloquant | | `instanceRef` ne désigne aucune instance, ou aucune à prendre par défaut (2.8) |
| `InstanceAmbiguous` | bloquant | oui | pas d'`instanceRef` et plusieurs instances dans le namespace |
| `InstanceNotAllowed` | bloquant | oui | instance d'un autre namespace hors consentement, ou hors du scope de l'opérateur |
| `InstanceBindingChanged` | bloquant | oui | `instanceRef` désigne désormais une autre instance que `status.instance` |
| `InstanceNotReady` | bloquant | | l'instance existe mais n'est pas (encore) `Ready` ; le message reprend sa raison |
| `InstanceInUse` | bloquant | | instance en suppression tant que des CR y sont liés (4.1) |
| `TokenSecretMissing` | bloquant | | Secret du token (admin external ou opérateur fourni) absent ou clé absente |
| `TokenSecretNotAllowed` | bloquant | oui | Secret du token sans le label `batlehub.weebo.io/instance-token: "true"` (2.11) |
| `SecretNotAllowed` | bloquant | oui | Secret de `configLayers`/`credentials`/`configFrom` sans le label `batlehub.weebo.io/credential: "true"` (2.11) |
| `InstanceUnreachable` | bloquant | | réseau, timeout, 502/504, `/livez` muet |
| `OperatorUnauthorized` | bloquant | | 401/403 ; ou `GET /api/v1/me` rend un rôle autre qu'`admin` (le message dit le rôle) |
| `OperatorTokenShadowed` | bloquant | oui | la config ne déclare plus le token de l'opérateur (couche credentials en managed, `spec.config` en external, 6.3) |
| `ConfigInvalid` | bloquant | oui | le parser refuse la config rendue (`Strict`), ou une couche n'est pas du TOML |
| `ConfigLayerMissing` | bloquant | | ConfigMap/Secret de `configLayers`/`credentials`/`configFrom` absent |
| `ConfigRejected` | bloquant | oui | l'instance refuse la config (dry-run ou chargement) ; re-stage au plus toutes les 10 min (6.1) |
| `ConfigPropagating` | bloquant | | Secret pas encore vu par tous les pods, ou reload en cours ; le message nomme les pods en retard |
| `NoReadyPod` | bloquant | | aucun pod proxy prêt pour approuver |
| `WorkloadNotReady` | bloquant | | réplicas désirés pas disponibles/à jour (managed) |
| `HotReloadDisabled` | bloquant | | 503 des endpoints de config, ou un pod rapporte le hot reload désactivé alors que la spec dit le contraire |
| `ConfigReadOnly` | bloquant | oui | external : première couche non inscriptible |
| `RestartForbidden` | bloquant | oui | external : changement de clé à redémarrage avec `manageConfig` ; le push est retenu (6.6) |
| `InstanceConfigUnmanaged` | bloquant | oui | registry sur une instance external sans `manageConfig` (4.2) |
| `OwnedObjectConflict` | bloquant | oui | managed : un objet à créer existe déjà sans être à l'opérateur (6.5) |
| `RemoteRejected` | bloquant | oui | 400 de l'API admin sur la gouvernance (dont version inexistante) |
| `RemoteNotFound` | bloquant | | référence absente côté batlehub (registry inconnue de l'instance) |
| `RemoteError` | bloquant | | 500 ou réponse non prévue de l'API admin |
| `GrantStorageUnavailable` | bloquant | | stockage des grants non configuré (503) |
| `GrantConflict`, `PolicyConflict` | bloquant | oui | grant/policy en place qui n'est pas de ce CR, ou autre CR sur la même coordonnée (4.6) |
| `GrantHeldByOwnership` | bloquant | oui | 409 : le sujet détient ces verbes par l'ownership |
| `ExemptionNotPermitted` | bloquant | oui | 403 de l'exemption : `gates:exempt` non accordé à l'opérateur (4.5) |
| `DuplicateRegistryName` | bloquant | oui | même `name` qu'une registry rendue avant, ou qu'une entrée de la config d'une instance d'un autre namespace (4.2) |
| `NamespaceNotAllowed` | bloquant | oui | `${` dans une registry d'un autre namespace |
| `InstanceRejected` | bloquant | | l'instance refuse la config qui contient la registry |
| `MaintenanceFailed`, `MaintenanceTimeout`, `MaintenanceInterrupted` | bloquant | | maintenances (4.3) |
| `LeavesWatchScope` | bloquant | | refus du webhook `/scope` du kit (`ScopeGuard`) : un CR qui porte encore le finalizer sortirait du `watch.labelSelector` |
| `KubernetesApiError` | bloquant | | erreurs de l'opérateur avant le status (Event) |
| `RestartRequired` | advisory | | `reload.restart: Never` ou external : les clés en attente dans le message |
| `ConfigHeld` | advisory | | `reload.strategy: Manual`, hash retenu dans le message |
| `ConfigWarnings` | advisory | | `warnings[]` non vide |
| `UnresolvedPlaceholders` | advisory | | 2.6 |
| `ConfigInvalidLenient` | advisory | | refus du parser ignoré par `Lenient` |
| `RegistrySelectorIgnored` | advisory | | `registrySelector.namespaces.from` autre que `Same` sur un opérateur limité à un namespace (7.1) |
| `TokenReviewUnavailable` | advisory | | `autoTokenReview` demandé sur un opérateur limité à un namespace : pas de ClusterRoleBinding (7.1) |
| `RegistrySuspended`, `MaintenanceRunning`, `MaintenanceSuspended`, `SuspiciousGrant`, `ExemptionExpired` | advisory | | par kind |
| `ConfigReloaded`, `ConfigRolledOut`, `RestartInterrupts`, `MaintenanceStarted`, `Revoked`, `Released` | advisory | | Events seulement (`announce_change`, `finalize`) ; `RestartInterrupts` en `Warning` |

Renommés par rapport à la v2 : `AmbiguousDefaultInstance` →
`InstanceAmbiguous` (code du gabarit) ; `RemoteConflict` disparaît (le
409 n'a qu'un sens, `GrantHeldByOwnership`).

Ordre de priorité pour `Ready` d'une instance (première cause vraie) :
`InvalidSpec` → `OwnedObjectConflict` → `ConfigLayerMissing` →
`SecretNotAllowed` → `ConfigInvalid` → `OperatorTokenShadowed` →
`TokenSecretMissing` → `TokenSecretNotAllowed` → `WorkloadNotReady` →
`InstanceUnreachable` → `OperatorUnauthorized` → `HotReloadDisabled` /
`ConfigReadOnly` / `RestartForbidden` → `ConfigRejected` → `NoReadyPod` →
`ConfigPropagating`. Les causes masquées restent lisibles dans les
champs du status (`appliedConfigHash`, `pods[]`, `restartKeys[]`).
Pendant la suppression, `InstanceInUse` remplace toutes les autres.

Sévérité : les conditions à part de la v0.1 (`ConfigValid`,
`ConfigApplied`, `WorkloadReady`, `AdminApiReachable`,
`OperatorAuthorized`) deviennent des raisons de `Ready` ; ce qui ne
bloque pas l'usage de l'instance (`RestartRequired`, `ConfigHeld`,
warnings) devient advisory, à côté de `Ready: True`.

## 6. Mécanismes transverses

### 6.1 Cycle de vie d'une config (instance managed)

```
BatleHubLocalInstance ──► rendu + validation ──► apply des objets possédés ──► attente des pods
                     token opérateur        Secret <name>-config              │
                     toujours déclaré ?     ServiceAccount, Service           ▼
                                            PVC (filesystem)           chaque pod proxy prêt :
                                            Deployment(s)              GET /admin/config/content
                                            HPA / Ingress / PDB /      == fichier écrit ?  non : ConfigPropagating, 15 s
                                            NetworkPolicy / CRB               │ oui
                                                                              ▼
                                                      config nouvelle : POST /admin/config/validate (une fois)
                                                                        POST /admin/config/reload (chaque pod)
                                                      régime stable :   GET  /admin/config/pending
                                                                        stagé par le watcher : POST …/pending/apply
                                                                              │
                                                                              ▼
                                                            status : Ready, hashs, warnings
```

Le use case `reconcile_instance` est découpé en étapes pures (`domain` :
rendu, hashs, plan de rollout, décision d'approbation) et en appels de
ports (`WorkloadStore`, `AdminGateway` par pod). Le controller ne fait
que câbler.

**Deux hashs**

- `configHash` : SHA-256 du fichier rendu complet. Quand il diffère de
  `appliedConfigHash`, l'opérateur attend que le Secret monté atteigne
  chaque pod, puis approuve le reload sur chacun.
- **Hash de redémarrage** : SHA-256 des seules clés à redémarrage (2.4).
  Posé sur le pod template (`batlehub.weebo.io/config-hash`) : un
  changement de ces clés roule les pods (Event `ConfigRolledOut`), tout
  autre changement non.
  - `reload.restart: Never` : l'annotation garde sa valeur et l'advisory
    `RestartRequired` nomme les clés jusqu'au prochain redémarrage.
  - `hotReload: false` : l'annotation porte tout le `configHash`, chaque
    changement est un redémarrage, rien n'est demandé à l'API de reload.
  - Workers (`--roles worker`, pas d'API de reload) : leur template porte
    toujours tout le `configHash`.

**Protocole d'approbation**

1. Lister les pods proxy prêts et non en terminaison ; les appeler par IP
   sur le port qu'ils servent réellement (qui peut retarder sur
   `server.port` tant qu'un redémarrage est retenu ; idem pour le port du
   conteneur, les probes et le Service).
2. Config nouvelle : quand chaque pod rapporte le fichier de l'opérateur,
   un seul `POST /admin/config/validate` (dry-run) — une config que tous
   refuseraient n'arrive sur aucun. Puis `POST /admin/config/reload` sur
   chaque pod : c'est l'approbation. batlehub relit le fichier et applique
   le pending s'il a déjà stagé ces octets, remplace un pending plus
   ancien, ou charge lui-même le fichier si son watcher n'a rien vu.
   Approuver directement le pending pourrait confirmer une révision qui
   n'est pas celle sur disque.
3. Régime stable : un reload stagé par le watcher depuis le fichier
   appliqué (couche credentials arrivée en retard) est approuvé via
   `POST /admin/config/pending/apply`.
4. Un pending stagé par quelqu'un d'autre (éditeur de config web) n'est
   jamais approuvé ; quand l'opérateur a une config à appliquer, il est
   jeté (le fichier sur disque est celui de l'opérateur).
5. `appliedConfigHash` avance quand chaque pod est passé sans refus.
   Chaque reload apparaît dans l'audit `config_changes` de batlehub sous
   le `user_id` de l'opérateur, et un Event `ConfigReloaded` est publié.
   Un pod qui refuse après que d'autres ont accepté est rapporté avec la
   liste des pods déjà passés : batlehub ne sait pas annuler un reload.

**Nonce de re-stage** (simplifié par le reload par hash, §11.1)

batlehub ne stage rien pour des octets identiques à sa dernière
_tentative_ de chargement. Si cette tentative a échoué, ou si son pending
a expiré (opérateur arrêté, pods non prêts pendant 10 minutes), les deux
appels répondent « pas de pending » / « expiré » pour toujours. Alors :

- l'opérateur vérifie que l'instance accepte la config (dry-run) ;
  refusée : `ConfigRejected` avec le message ;
- acceptée : il incrémente `status.reloadNonce` et réécrit le fichier
  avec un commentaire final `# weebo-batlehub reload-nonce: N`. Nouveaux
  octets, nouveau stage sur chaque pod, approbation à la passe suivante.
  Le nonce n'entre pas dans `configHash`. Les pods qui avaient déjà
  appliqué la config la re-stagent aussi (reload sans effet), ce qui fait
  converger un échec partiel.

**Backoff des refus** : une config qui passe le dry-run mais échoue au
chargement tournerait en boucle (refus, pas de pending, re-stage, refus).
Un refus enregistre `rejectedConfigHash` et `lastRejectionTime`, et la
même config n'est re-stagée qu'au plus une fois toutes les 10 minutes
(`due_in`), le refus restant dans `Ready`. Un changement de spec (nouveau
hash) passe immédiatement. Même règle pour les push external.

**Hot reload désactivé par l'environnement** : un pod qui rapporte le hot
reload désactivé alors que la spec dit le contraire (variable posée via
`env`/`envFrom`) donne `HotReloadDisabled`, dont le message demande
`hotReload: false`.

**Stratégie Manual** : le Secret garde la config appliquée,
`pendingConfigHash` nomme la config retenue (les workers restent aussi
sur l'appliquée), advisory `ConfigHeld`. Libérée en posant
`batlehub.weebo.io/approved-config-hash: <hash exact>` (à la main ou via
une maintenance `configReload`). Une modification ultérieure a un autre
hash et est retenue à nouveau.

### 6.2 Stratégie de mise à jour

- Stockage filesystem sur un claim `ReadWriteOnce`/`ReadWriteOncePod` :
  un seul écrivain, un pod de surge sur un autre nœud attendrait le volume
  pour toujours. Le Deployment proxy passe en `Recreate`, une interruption
  bornée annoncée par l'Event `Warning` `RestartInterrupts` qui nomme les
  clés en cause.
- Tout le reste (S3, cache éphémère, RWX) : `RollingUpdate` avec
  `maxUnavailable: 0`, aucun redémarrage ne réduit la capacité.
- `spec.managed.updateStrategy` force la stratégie ;
  `status.updateStrategy` montre la stratégie effective.
- Redémarrage sans interruption = la forme HA de batlehub : S3, backend
  de cache partagé, au moins 2 réplicas et un PDB.

### 6.3 Token de l'opérateur

- Généré une fois dans le Secret `<name>-operator-token` (owner reference
  sur l'instance), jamais ré-appliqué, donc jamais tourné sous une
  instance en marche. Rotation volontaire : supprimer le Secret, ce qui
  change la couche `auth` et redémarre les pods (`auth` est à
  redémarrage).
- Déclaré dans la config comme un `[[auth]] type = "token"`,
  `role = "admin"`, dont la `value` est le hash **Argon2id** au format PHC
  avec les paramètres de `hash_static_token` de batlehub (m=19456, t=2,
  p=1). Le rôle `admin` porte `config:read` et `config:write` au niveau
  instance, ce qu'exige l'approbation d'un reload.
- Le sel est dérivé du token : le hash, donc le fichier rendu, est stable
  d'une passe à l'autre. Le hash est calculé une fois par token et mis en
  cache dans le processus (Argon2id à m=19456 KiB est volontairement coûteux :
  sans cache, il pèserait sur le budget CPU `weebo-kit-perf` de chaque
  reconcile).
- Le token brut ne quitte jamais le Secret : il n'atteint pas le pod, pas
  même en variable d'environnement.
- Le bloc `[[auth]]` dérivé est stocké dans son propre Secret,
  `<name>-operator-auth` (clé `auth.toml`), ré-appliqué à chaque passe.
- `operatorAccess.generateToken: false` : le token de l'utilisateur
  (`tokenSecretRef`) est utilisé, à charge pour lui de le déclarer dans
  `config.auth`.
- **Masquage** : la couche `credentials` est fusionnée après celle de
  l'opérateur. Si elle déclare ses propres `[[auth]]` sans clé unique,
  batlehub remplace tout le tableau, entrée opérateur comprise, et
  l'opérateur se verrouillerait dehors au prochain redémarrage. Avant tout
  apply, l'opérateur fusionne donc la couche credentials comme batlehub
  (2.3) et vérifie que son token est toujours déclaré ; sinon
  `OperatorTokenShadowed` et rien n'est appliqué (solution : ajouter le
  bloc de `<name>-operator-auth` à la couche credentials).
- À l'exécution, `OperatorUnauthorized` rapporte un refus de l'instance
  (401 : jeton inconnu ; 403 : sans `config:write`) ou un rôle autre
  qu'`admin` lu sur `GET /api/v1/me`.
- **External avec `manageConfig`** : même risque, autre source. Le token
  est celui de `adminTokenSecretRef` ; si `spec.config` (et ses couches)
  ne déclare plus de `[[auth]]` qui l'accepte, le push réussirait et
  l'opérateur serait enfermé dehors au prochain redémarrage de
  l'instance. Avant tout push, l'opérateur vérifie qu'une entrée
  `[[auth]] type = "token"` de la config fusionnée accepte le token
  (vérification du hash Argon2id, ou valeur en clair) ; sinon
  `OperatorTokenShadowed` et rien n'est poussé. Une couche credentials de
  l'instance que l'opérateur ne voit pas peut encore la masquer : la doc
  le dit, l'opérateur ne peut pas le détecter.

### 6.4 Couche credentials

- Le seul fichier monté mais **non rendu** par l'opérateur : batlehub le
  lit comme second `--config`, donc les tokens upstream n'apparaissent ni
  dans le Secret rendu ni dans le status.
- Pour qu'une rotation soit quand même un changement de config,
  l'opérateur hashe la couche (`status.credentialsHash`) et ajoute le
  hash en commentaire final du fichier rendu
  (`# weebo-batlehub credentials-revision: sha256:…`). Une rotation produit
  un nouveau `configHash`, attend que les deux Secrets atteignent le pod,
  et hot-reload (qui relit toutes les couches). Elle ne touche jamais le
  hash de redémarrage.
- Les deux fichiers sur disque étant ceux de l'opérateur, un pending stagé
  par le watcher de batlehub (credentials arrivées après le reload) est
  déjà l'état désiré : il est approuvé en régime stable plutôt que laissé
  expirer.

### 6.5 Instance managed : objets possédés

Secret de config, Secrets du token et du bloc `[[auth]]`, ServiceAccount,
Service, PVC (stockage filesystem), Deployment proxy, Deployment worker,
HPA, Ingress, PDB, NetworkPolicy : tous en SSA, avec owner reference sur
l'instance (supprimer le `BatleHubLocalInstance` supprime l'instance).

**Pas d'adoption implicite** (règle de forgejo, « collision → rejet ») :
avant le premier apply d'un objet, l'opérateur le lit ; un objet du même
nom qui existe sans owner reference vers cette instance ni label
`app.kubernetes.io/managed-by: weebo-batlehub` n'est pas repris (le SSA le
ferait en silence) : `Ready: False`, `OwnedObjectConflict`, le message
nomme l'objet. Même règle pour le POST du Secret `<name>-operator-token`
(un 409 sur un Secret étranger est ce conflit, pas un succès). Pour
reprendre un objet existant, l'utilisateur pose lui-même le label.

Exception : le ClusterRoleBinding qui donne à une instance utilisant le
provider d'auth `kubernetes` le ClusterRole `<release>-tokenreview` du
chart (TokenReview `create`, rien d'autre). Un objet cluster-scoped ne
peut pas avoir de propriétaire namespacé : le finalizer du kit
(`batlehub.weebo.io/finalizer`) le supprime. Son nom est un hash du
namespace et du nom de l'instance (unique et court). L'opérateur n'écrit
jamais de ClusterRole lui-même ; il a le verbe `bind` sur ce seul
ClusterRole (`resourceNames`), pas l'escalade générale.

### 6.6 Instance external

- Lit le token admin dans le Secret (relu à chaque reconcile, comme le
  `tokenSecretRef` du gabarit), appelle `/livez` et
  `/admin/config/warnings` pour remplir le status.
- Avec `manageConfig` : compare la config rendue avec
  `GET /admin/config/content`. Si elles diffèrent, valide contre
  l'instance (`POST /admin/config/validate`), pousse avec
  `POST /admin/config/from-content`, puis approuve le pending ainsi créé.
- `from-content` répondant `pending_created: false` = l'instance a déjà vu
  ces octets exacts : pas de succès revendiqué, incrément du nonce et
  nouveau push avec le commentaire (ignoré dans la comparaison).
- Avec `podSelector` (instance du chart batlehub dans le cluster) : les
  réplicas ne partagent pas un reload ; le push passe par un pod, puis
  chaque pod sélectionné est approuvé par IP comme en managed. Sans
  `podSelector`, une instance external à plusieurs réplicas n'est pas
  supportée avec `manageConfig` (advisory dans la doc, pas de détection
  possible).
- Prérequis côté instance : première couche de config inscriptible, hot
  reload actif. Sinon `ConfigReadOnly` ou `HotReloadDisabled`, sans
  boucle d'erreur.
- `Manual` fonctionne comme en managed.
- Un changement de clé à redémarrage donne `RestartForbidden` (bloquant)
  et l'advisory `RestartRequired` : l'opérateur ne peut pas redémarrer ce
  qu'il ne possède pas (l'action `restart` est refusée sur une instance
  external). **Le push est retenu** tant que la config désirée change une
  clé à redémarrage par rapport à celle de l'instance : pousser des clés
  qui ne prendraient effet qu'au prochain redémarrage, fait par un tiers à
  un moment inconnu, n'est pas un état que l'opérateur sait suivre.
  Retirer le changement de clé, ou redémarrer l'instance hors opérateur
  après avoir aligné sa config, lève le blocage.

### 6.7 Watches et resynchronisation

Squelette `controller(api)` du kit pour chaque kind (prédicats, concurrence
`WEEBO_RECONCILE_CONCURRENCY`), plus, sur le controller d'instance :

- objets possédés : Deployment, Secret, Service (`owns`) ;
- `BatleHubRegistry`, ramenées à leur instance ;
- ConfigMaps **en métadonnées seulement** : aucune donnée en cache, et un
  changement de données incrémente quand même le `resourceVersion` vu par
  le watch. Une fonction pure (`domain`) liste ce qu'une instance lit
  (`configLayers`, `configFrom` des registries dans leur namespace) et
  ramène un changement aux instances concernées.
- **Secrets : pas de watch** (D9 ; `list/watch` sur `secrets` donnerait
  la lecture de tous les Secrets). Ceux qu'une instance lit
  (`configLayers`, `credentials`, tokens, CA, `secretKeyRef` de son env,
  `configFrom`) sont relus à chaque reconcile, par nom, et leur hash
  entre dans `configHash` : une rotation est prise en compte à la
  resynchronisation suivante (≤ 300 s ±20 %). Si D9 est refusée, la même
  fonction pure ramène un changement de Secret à ses instances, et le
  chart ajoute `secrets` en `list/watch` à `params.clusterRules`, avec la
  justification dans la doc de sécurité ;
- Pods proxy (métadonnées) : un pod qui devient prêt relance
  l'approbation sans attendre les 15 s ;
- Namespaces, pour le mode `Selector` (mode cluster seulement, 7.1).

Resynchronisation de fond : `requeue_after` du kit (300 s ±20 %).

Les controllers de gouvernance et de maintenance surveillent aussi les
`BatleHubLocalInstance` (une instance qui devient `Ready` relance ses CR,
qui sortent de `InstanceNotReady`).

### 6.8 Webhook de validation

Deux couches refusent un objet invalide avant stockage :

- **CEL** dans les CRD (évaluées par l'apiserver seul) : un seul mode par
  instance, `schedule` non vide, params requis par action, sélecteur de
  namespaces requis avec `Selector`, coordonnées de gouvernance
  immuables, `policy` ou `exemptions` présents.
- **Webhook** (`Admission` du kit, `params.admitted` du chart) pour ce qui
  demande un autre objet ou le parser :

| Kind | Refusé (code) |
| --- | --- |
| `BatleHubLocalInstance` | aucune config, `spec.config` qui n'en est pas une (`InvalidSpec`, `ConfigInvalid`) ; sans `configLayers`, `spec.config` refusé par le parser en `Strict` (`ConfigInvalid`) ; managed (M4) : la couche credentials masque le token opérateur (`OperatorTokenShadowed`). Jamais pour une couche ni une registry (révisé au M2 : elles se corrigent sans toucher au CR, ou appartiennent à une autre équipe) |
| `BatleHubMaintenance` | `schedule` ou `params.before` illisible (`InvalidSpec`) ; `restart` sur une instance external (`InvalidSpec`) ; un `params.registry` absent de la config rendue, de la couche credentials et des registries rattachées (`InvalidSpec`) |
| `BatleHubRegistry` | `${` dans une registry d'un autre namespace (`NamespaceNotAllowed`) ; `type` ou nom vide, fragment `configFrom` qui n'est pas du TOML (`ConfigInvalid`) |
| `BatleHubPackageGrant` | même coordonnée et même sujet qu'un autre CR (`GrantConflict`) |
| `BatleHubPackagePolicy` | même coordonnée qu'un autre CR (`PolicyConflict`) ; gate réglé et exempté (`InvalidSpec`) |

- Chaque refus est un refus que les reconcilers feraient de toute façon,
  déplacé du status vers `kubectl apply`. Ce qui peut encore changer tout
  seul (couche pas encore créée, instance absente) n'est pas refusé : il
  apparaît dans le status.
- Le kit accepte toujours `DELETE` et les `UPDATE` sans changement de
  `spec` (finalizer, `run-now`, `approved-config-hash`) : une instance
  devenue invalide via une couche reste supprimable.
- Servi par tous les réplicas, leader ou non, certificat cert-manager
  relu à chaud (chart et `webhook_server` du kit). `failurePolicy: Fail`.
  Le timeout doit couvrir un rendu complet (couches et registries
  comprises) : mesuré au M2, à régler par les values du chart.

### 6.9 Leader election, santé, arrêt

Tout vient du kit (`leader`, `health`, `Shutdown`, `webhook_server`) :
plusieurs réplicas, un seul réconcilie ; probes, métriques et webhook
répondent en standby ; jauge `weebo_batlehub_leader` ; drain
`WEEBO_SHUTDOWN_DRAIN_SECONDS`. Rien de propre à batlehub.

### 6.10 Nettoyage

- Objets possédés : owner references (6.5).
- ClusterRoleBinding TokenReview : finalizer (6.5).
- Instance : finalizer, `InstanceInUse` tant que des CR y sont liés
  (4.1).
- Gouvernance : finalizer (4.6).
- Les séries de métriques d'une instance supprimée sont retirées au
  nettoyage.

### 6.11 Métriques

- Du kit : `weebo_batlehub_reconcile_total{kind,result,reason}`,
  `weebo_batlehub_reconcile_duration_seconds`,
  `weebo_batlehub_webhook_decisions_total`, `weebo_batlehub_leader`.
- Propres (OpenTelemetry, comme le kit) :
  `weebo_batlehub_maintenance_runs_total{action,result}`,
  `weebo_batlehub_instance_ready`, `weebo_batlehub_instance_restart_required`,
  `weebo_batlehub_instance_config_warnings{code}` (un warning qui
  disparaît emporte sa série), `weebo_batlehub_admin_requests_total{endpoint,status}`.
- Déclarées dans la config de la doc pour la page « Metrics » ; alertes
  propres (`params.alerts`) : instance non prête > 15 min, redémarrage
  en attente > 24 h, maintenances en échec.

### 6.12 Variables d'environnement de l'opérateur

Celles du kit (`WEEBO_METRICS_ADDR`, `LOG_FORMAT`,
`OTEL_EXPORTER_OTLP_ENDPOINT`, `WEEBO_RECONCILE_CONCURRENCY`,
`POD_NAMESPACE`, `LEASE_NAME`, `WEBHOOK_PORT`, `WEBHOOK_TLS_*`,
`WEEBO_SHUTDOWN_DRAIN_SECONDS`), posées par le chart du kit. Propres
(`params.env`) :

| Variable | Rôle |
| --- | --- |
| `WEEBO_BATLEHUB_DEFAULT_IMAGE` | Image batlehub par défaut des instances managed (proxy et worker). |
| `WEEBO_BATLEHUB_TOKENREVIEW_CLUSTERROLE` | Nom du ClusterRole TokenReview du chart. |
| `WEEBO_BATLEHUB_ADMIN_TIMEOUT_SECONDS` | Timeout des appels admin (hors maintenances, bornées par `timeoutSeconds`). |

## 7. Chart Helm de l'opérateur

`deploy/charts/weebo-batlehub` sur `weebo-operator-lib` (gabarit) :

- `_params.tpl` : `group: batlehub.weebo.io`, les 5 kinds, `namespacedKinds`
  = les 5 (tous namespacés), `admitted` = les 5, `env` (6.12), `egress`
  vers les instances (`networkPolicy.egress.batlehub` : pods batlehub du
  cluster sur leur port HTTP, plus les URLs external), `clusterRules`,
  `alerts`.
- `clusterRules` : `apps/deployments`, `services`, `configmaps`
  (lecture), `persistentvolumeclaims`, `serviceaccounts`,
  `networking.k8s.io/ingresses`, `networkpolicies`,
  `policy/poddisruptionbudgets`, `autoscaling/horizontalpodautoscalers`
  en `get/list/watch/create/patch/delete` ; `pods` en `get/list/watch` ;
  `namespaces` en `get/list/watch` ; `clusterrolebindings` en
  `create/patch/delete` et `bind` sur le seul ClusterRole TokenReview.
  Les Secrets lus par nom, les Events et les kinds (status, finalizers)
  viennent du ClusterRole du kit ; `params.clusterSecrets: true` est posé
  explicitement (l'opérateur lit et écrit des Secrets dans chaque
  namespace qui a une instance). Le watch de métadonnées des Secrets
  (6.7) demanderait `list/watch` sur `secrets`, que le kit n'accorde
  jamais : voir D9.
- Template propre en plus d'`operator.yaml` : le ClusterRole
  `<release>-tokenreview` (TokenReview `create`).
- Values propres : `defaults.image` (→ `WEEBO_BATLEHUB_DEFAULT_IMAGE`),
  `tokenReview.enabled`, `networkPolicy.egress.batlehub`. Le reste est le
  contrat du kit (`replicaCount`, `leaderElection`, `webhook`,
  `certManager`, `metrics`, `serviceMonitor`, `prometheusRule`, `probes`,
  `resources`…).
- CRD : templates `crds.install` + `helm.sh/resource-policy: keep`
  (`task recu` → `helm:crds`).
- `prometheusRule.enabled` exige `metrics.prometheus.enabled` (le chart
  du kit fait échouer le rendu sinon, T5) : les alertes propres
  (`params.alerts`) en dépendent aussi.

### 7.1 Modes du scope du kit (D6)

Le chart et le binaire du kit savent restreindre l'opérateur
(`watch.namespace`, `watch.labelSelector`, `watch.clusterKinds`,
`WatchScope`, webhook `/scope` et `ScopeGuard`). batlehub n'a aucun kind
cluster-scoped ; ce qu'il fait dans chaque mode :

| Mode | Comportement |
| --- | --- |
| cluster (défaut) | Tout ce document. |
| `watch.namespace` | Les 5 kinds passent dans le Role `-watch` du namespace. Refus : pas de registry cross-namespace (`RegistrySelectorIgnored` sur une instance qui demande `All`/`Selector`), pas de watch des Namespaces, pas de ClusterRoleBinding TokenReview (`autoTokenReview` demandé : advisory `TokenReviewUnavailable`, l'utilisateur lie TokenReview lui-même). Limite connue : `params.clusterRules` (Deployments, Services, PVC… du mode managed) restent dans le ClusterRole, le chart du kit n'ayant pas de règles propres pour le Role `-watch` (§11.2) : le mode limite ce que l'opérateur **réconcilie**, pas tout ce qu'il **peut** écrire. |
| `watch.clusterKinds: false` (tout en Roles) | **Partiel**, à refuser par le chart dès que possible : sans ClusterRole, `params.clusterRules` disparaissent — couches ConfigMap, `configFrom` ConfigMap et `podSelector` échouent (`KubernetesApiError`) ; le mode managed ne pourrait rien écrire. Le `fail` dans `_params.tpl` casse le rendu de fumée du kit : il attend `params.watchRules` (§11.2). Documenté comme tel (values, guide d'installation). |
| `watch.labelSelector` | Supporté tel quel (kit) : `LeavesWatchScope` au webhook `/scope`. Pas une frontière de sécurité (RBAC ne filtre pas par label). |

**Avertissement de sécurité** (dans le `NOTES.txt` et la doc) : un
opérateur qui écrit des Deployments et lit des Secrets dans un namespace
y détient ce que peut faire un pod avec n'importe quel ServiceAccount et
n'importe quel Secret. Créer un `BatleHubLocalInstance` revient à pouvoir faire
tourner un pod et lire un Secret dans ce namespace (le token admin et les
couches d'une instance external sont envoyés à son `url`) : les kinds se
donnent comme on donne les pods. Le Role d'exemple du kit
(`rbac.namespacedExample`) doit le dire. Les labels d'opt-in (2.11)
bornent ce qui peut sortir : seuls les Secrets que leur propriétaire a
labellisés `instance-token` ou `credential` sont lus pour être envoyés.

## 8. Correspondances avec batlehub

### Variables d'environnement

| Variable | Origine |
| --- | --- |
| `${VAR}` dans le TOML | `spec.managed.env`/`envFrom` (managed) ; environnement de l'instance (external). |
| `PROXY_CACHE__*` (15 overrides : `SERVER__HOST/PORT/STATIC_DIR`, `DATABASE__URL/MAX_CONNECTIONS/MIN_CONNECTIONS/ACQUIRE_TIMEOUT_SECS`, `STORAGE__PATH/BUCKET/REGION/ENDPOINT_URL`, `OTEL__ENDPOINT/SERVICE_NAME`, `PROXY__URL/USERNAME/PASSWORD/NO_PROXY`) | N'importe quelle entrée `env` ; préférer la clé TOML (sinon le hash de redémarrage ne voit pas le changement). |
| `BATLEHUB_CONFIG` | Non utilisé : `--config` est passé explicitement. |
| `BATLEHUB_DISABLE_HOT_RELOAD` | `spec.managed.hotReload: false`. |
| `KUBERNETES_SERVICE_HOST/PORT` | Posées par le kubelet ; le provider `kubernetes` exige `automountServiceAccountToken`, activé dans ce cas. |
| `TMPDIR` | `/tmp/batlehub` sur le conteneur worker. |

### Flags du serveur

| Flag | Couvert par |
| --- | --- |
| `--config` (répétable) | `spec.config` (+ couches fusionnées) → premier fichier ; `spec.credentials` → second. |
| `--roles` | `worker` présent → proxy en `proxy`, worker en `worker` ; absent → `proxy,worker`. |
| `dump-spec`, `hash-token`, `explain-config` | Pas des flags de workload (`dump-spec` alimente `task gen:client`). |

### Chart Helm batlehub → CRD (migration, et entrée de l'importeur)

| Valeur du chart | Champ du CRD |
| --- | --- |
| `replicaCount` | `spec.managed.replicas` |
| `image.*`, `imagePullSecrets` | `spec.managed.image.*`, `imagePullSecrets` |
| `serviceAccount.create/name/annotations`, `serviceAccount.rbac.autoTokenReview` | `spec.managed.serviceAccount.*` |
| `serviceAccount.automountServiceAccountToken` | dérivé de `config.auth` |
| `podAnnotations`, `nodeSelector`, `tolerations`, `affinity`, `podSecurityContext`, `securityContext`, `resources`, `env`, `envFrom` | mêmes noms sous `spec.managed` |
| `service.*`, `ingress.*` | `spec.managed.service.*`, `ingress.*` (`enabled` → présence) |
| `config.*` | `spec.config.*` (clés identiques ; entiers écrits en entiers) |
| `credentials.config` | rendre en TOML dans un Secret, référencé par `spec.credentials` |
| `credentials.existingSecret/key` | `spec.credentials.name/key` |
| `podDisruptionBudget.*`, `persistence.*` | `spec.managed.*` |
| `worker.*` | `spec.managed.worker.*` (`scratch.sizeLimit` → `scratchSizeLimit`) |
| `externalManifest[]` | `spec.configLayers` pour du TOML ; `extraVolumes`/`extraVolumeMounts` pour des fichiers |
| `networkPolicy.ingressFrom/egressTo` | `spec.managed.networkPolicy.*` |
| `trivy.enabled` | hors périmètre : installer Trivy et pointer `config.scanners.trivy.endpoint` |

Garder une release Helm de batlehub et la piloter (`external` +
`podSelector`) est l'autre chemin, sans migration (D1).

## 9. Tests, qualité, outillage

### 9.1 Couches de tests

| Couche | Exerce | Tâche |
| --- | --- | --- |
| Unitaires | `domain` : rendu, fusion (via le port, avec le vrai parser), classification des redémarrages, placeholders, cron, params, rattachement, comparaison des grants, priorité des raisons. `application` : chaque use case contre `FakeBatleHub`/`FakeWorkload`, dont **tous les cas limites du reload** ci-dessous. | `task test` |
| Contrat | `HttpAdminGateway` + client généré contre wiremock (route, verbe, query, forme du body, mapping des erreurs vers `GatewayError`) ; formes tirées de l'OpenAPI. | `task test` |
| Schéma | CRD générés (CEL, objets ouverts, clés de list-map, colonnes, enum des 30 actions), YAML commité = régénéré, chaque exemple de la doc validé contre le schéma (`weebo-crd-docs`). | `task recu` + CI |
| envtest | `weebo-kit-testkit` : vrais `etcd` + `kube-apiserver`, controllers complets avec une instance `external` vers wiremock ; CEL, SSA, sous-ressource status, watch de Secret, webhook en TLS. Pas de kubelet : le managed y est testé jusqu'aux objets écrits, pas aux pods. | `task test:all` |
| Live | Gateway et controllers contre un **vrai batlehub** (conteneur batlehub + Postgres, `task batlehub:container:start`, `.batlehub-test.env`) : reload réel, refus réels, grants et policies. C'est ce qui a manqué à la v0.1. | `task test:live-batlehub` |
| e2e | kind (`deploy/e2e/`, `e2e.yml` planifié et porte de `publish.yml`, 9.3), test d'upgrade compris : image et chart (2 réplicas sur la Lease), cert-manager, Postgres, instance managed jusqu'à `Ready`, maintenance, refus CEL et webhook, bascule de leader, hot reload, rotation de credentials, NetworkPolicy, changement à redémarrage sur cache RWO (`Recreate`), garbage collection, binding TokenReview à la suppression. | `task e2e` |
| Budget | `weebo-kit-perf` : binaire release contre envtest, 200 `BatleHubPackageGrant` sur une instance external wiremock ; `Budget::small_cluster()` ; rapport commité sous `docs/perf/`, `perf.yml` du kit chaque semaine. | `task perf` |

**Cas limites du reload, à porter comme spécification** (tests de use
case, puis live) : chaque pod proxy, propagation par pod, pending approuvé
ou reload demandé, re-stage avec nonce, refus, refus partiel, 401/403,
credentials masquant le token opérateur, pas de hot reload, workers,
approbation `Manual`, dédoublonnage external, external avec
`podSelector`.

### 9.2 Seuils et outillage

- `task coverage` (kit, `cargo llvm-cov`) : échoue sous 85 % de lignes,
  toutes couches comprises (live inclus en CI planifiée).
- `task lint` : `fmt --check`, `clippy -D warnings`, actionlint,
  hadolint ; `task lint:helm` : lint + smoke renders du kit.
- `task audit` : cargo-deny (dont `allow-git` pour le kit et batlehub),
  trivy, trivy config, npm audit (doc).
- `task recu` : client généré, CRD, copies dans le chart, pages de doc ;
  la CI échoue sur toute dérive.
- `task gen:client` / `task gen:bump BATLEHUB_VERSION=x.y.z` : spec
  OpenAPI, client, tag de `batlehub-config` et image par défaut ensemble.
- mise, Taskfile (chaque tâche avec `desc`, tâches multiples dans
  `.tasks/`), tâches partagées du kit incluses à distance et épinglées par
  checksum, `task kit:sync TAG=…`.
- cocogitto : `cog.toml` rendu depuis le kit (`task kit:cog`), hooks
  `cog verify`, `recu`/`lint`/`test`/`audit` avant chaque commit,
  `audit` et `test:all` avant chaque tag. Commits signés par
  l'utilisateur.
- `Containerfile` et `Containerfile.static` du gabarit (image
  principale et variante statique, celles que `publish.yml` du kit
  construit), `.grype.yaml` pour les exceptions de scan justifiées.
- Doc : site Fumadocs sur `@weebo/operator-docs` (`docs/`), pages CRD et
  pages de référence (codes de raison, Events, métriques, budget)
  générées ; contenu propre : guides (déployer une instance managed,
  piloter une release Helm existante, reload et `Manual`, gouvernance,
  maintenance), choix guidés du formulaire de manifeste (`CrdChoices` :
  mode managed/external, actions de maintenance et leurs params).

### 9.3 CI et release

Rien n'est écrit à la main : tout vient des workflows réutilisables du
kit, épinglés sur son tag, sur le modèle de weebo-forgejo.

- `ci.yml` appelle `checks.yml@v0.14.2` du kit (`lint`, `test`, `audit`,
  `helm`) et ajoute ses jobs propres : `test:all` (envtest), dérive de
  `recu`, build des deux images.
- `e2e.yml` (kind) : appelable (`workflow_call` avec `ref`), planifié,
  à la main, et **porte de la publication**.
- `publish.yml` sur tag `v*` : job `e2e` (le `e2e.yml` ci-dessus sur le
  tag) puis `publish` =
  `batleforc/weebo-operator-kit/.github/workflows/publish.yml@v0.14.2`
  (scan Grype `--fail-on high`, cosign keyless, SBOM, chart OCI après
  l'image, release GitHub ; amd64 par défaut, `arm64` en option). Seule
  l'image principale est une porte : `variants` déclare
  `Containerfile` `required: true` et `Containerfile.static`
  `required: false`, et l'e2e de la variante statique est en
  `continue-on-error` (leçon F5 de forgejo). `permissions: {}` par
  défaut, actions épinglées par SHA (celles du kit le sont déjà).
- **Test d'upgrade** dans l'e2e (`UPGRADE_FROM`) : installe le dernier
  chart publié, applique le scénario, met à jour vers le chart du
  checkout, vérifie que tout reste `Ready`. Sauté quand aucun chart n'est
  publié ou que c'est la même version — donc il ne tourne vraiment que
  sur un tag : le valider à la main sur une branche avant la première
  release qui l'exerce. Pièges vus sur forgejo (PR #9) : l'ancienne
  release doit recevoir les mêmes values que le scénario
  (`references.crossNamespace` y manquait), et tout `kubectl apply`
  contre son webhook doit être réessayé tant qu'il démarre.
- Miroir Forgejo/Harbor : hors kit, après la 0.1.0 (§12).

**Montée de version de batlehub** : `task gen:bump`, relire les notes de
version (nouvelles sections de config, nouvelles clés à redémarrage,
nouveaux endpoints admin), mettre à jour le catalogue d'actions, relancer
`test:live-batlehub`. Bump mineur de l'opérateur.

## 10. Jalons

Chaque jalon se termine par un passage de `test:live-batlehub` sur la
version cible, et ses constats (comportements réels de batlehub, écarts
avec ce document) sont ajoutés ici, sous « Constats du Mx ».

| Jalon | Contenu | Fini quand |
| --- | --- | --- |
| M0 | Repo généré par le gabarit du kit **v0.14.2** (rendu hors workspace, `task template:render` du kit comme modèle), renommages (§3), kind cluster du gabarit supprimé (D5), `LocalInstanceDirectory` (2.8), client généré, port `ConfigParser` (adaptateur vide jusqu'au M2), `ReasonCode` (§5, complet), `ci.yml`/`e2e.yml`/`publish.yml` branchés (9.3), doc vide publiée | `task test:all` et `task audit` verts ; CI verte sur `main` |
| M1 | `BatleHubLocalInstance` **external** sans `manageConfig` : `/livez`, `GET /api/v1/me` (rôle), warnings, version, `Ready` ; label `instance-token` (2.11) ; finalizer et `InstanceInUse` ; résolution d'instance des autres kinds (2.8) | envtest : `Ready`, `TokenSecretNotAllowed` sur un Secret non labellisé, `OperatorUnauthorized` sur un rôle non admin, `InstanceInUse` ; live : instance réelle `Ready`, token refusé → `OperatorUnauthorized` |
| M2 | **Prérequis : batlehub v1.6.0 publiée** (D4, D8 révisée) et `batlehub-config` épinglé dessus. external + `manageConfig` (push, validate, nonce, backoff, `Manual`, `RestartForbidden`, contrôle du token 6.3) + `podSelector` ; webhook `BatleHubLocalInstance` ; `BatleHubRegistry` (rattachement, doublons, `InstanceConfigUnmanaged`, label `credential`) ; **release 0.1.0-alpha.1** (D7) | live : cas limites du reload sur 2 réplicas du chart batlehub ; envtest : registries en doublon, Secret non labellisé ; alpha publiée par `publish.yml` du kit, porte e2e verte |
| M3 | `BatleHubPackageGrant`, `BatleHubPackagePolicy`, `BatleHubMaintenance` (catalogue **sans `restart`**, qui demande le managed) | live : dérive, conflit, `GrantHeldByOwnership`, échec partiel (status patché par sujet), révocation, exemptions et `ExemptionNotPermitted` ; maintenance au plus une fois (kill pendant un run, patch conditionnel) ; envtest : `InstanceInUse` avec des grants liés |
| M4 | `managed` : objets possédés (sans adoption implicite, `OwnedObjectConflict`), deux hashs, `Recreate`/`RollingUpdate`, token opérateur, credentials, worker, TokenReview ; action `restart` | e2e kind complet vert, test d'upgrade depuis l'alpha compris |
| M5 | `weebo-batlehub-importer` (release Helm → `BatleHubLocalInstance`, grants/policies → CR en pause) ; budget mesuré ; release 0.1.0 | release publiée de bout en bout |

### Constats du M0 (2026-10-14)

Repo `github.com/batleforc/weebo-batlehub` (public), commit `394cd62`,
CI, docs (GitHub Pages) et e2e kind verts au premier passage. Pas de
`test:live-batlehub` au M0 : la tâche et le conteneur batlehub arrivent
avec le M1.

- **Gabarit du kit v0.14.2** : il génère aussi un kind `BatleHubObject`
  (exemple), la commande `migrate-instance-ref` et la licence **MIT**
  (Cargo, labels d'image) alors que les opérateurs weebo sont Apache-2.0 :
  les trois sont retirés ici, la licence est à corriger dans le gabarit.
  `sharedWith` du `BatleHubLocalInstance` généré est retiré (2.8).
- **Forme de `BatleHubLocalInstance` au M0** : celle du gabarit (`url`,
  `tokenSecretRef`). Le M1 la remplace par `external`/`managed` (4.1) ;
  rien n'étant publié, ce n'est pas une rupture.
- **Fait en avance sur le M1** : le contrôle du rôle par
  `GET /api/v1/me` (`OperatorUnauthorized` sur un rôle autre qu'admin) et
  le label `instance-token` (`TokenSecretNotAllowed`), tous deux couverts
  par l'envtest `local_instance_controller`. Le finalizer et
  `InstanceInUse` restent au M1 (aucun kind ne se lie encore à une
  instance).
- **OpenAPI de batlehub** : committée dans batlehub (`ui/openapi.json`,
  versionnée avec chaque tag) : `task gen:spec` la télécharge par URL
  brute, sans construire batlehub. 316 chemins ; le patch
  `10-admin-api-only.jq` garde l'API admin et `/api/v1/me` (88 chemins,
  170 schémas atteignables). `/livez` n'est **pas** dans la spec (handler
  actix hors utoipa) : appelé directement.
- **openapi-generator 7.25** (OpenAPI 3.1 en bêta) : un `oneOf` de
  variantes enum à une valeur (`FlagKind` : `cve`, `malware`… ou
  `{other}`) produit un enum Rust qui ne compile pas : patch
  `20-merge-string-enum-variants.jq`.
- **D6 et le chart** : refuser `watch.clusterKinds: false` dans
  `_params.tpl` casse `task lint:helm` (le kit fait un rendu de fumée de
  ce mode). Au M0 il n'y a aucune règle propre (`clusterRules`), le mode
  fonctionne : le refus est reporté au M4, sauf si le kit gagne d'ici là
  `params.watchRules` (§11.2) ou un moyen d'exclure un rendu de fumée.
- **Page « Reason codes » générée** : le générateur du kit lit
  `error.rs` comme du texte : accolades équilibrées dans les doc comments
  (`${` seul le casse) et bras de `severity` qualifiés (`ReasonCode::X`,
  pas de `use ReasonCode::*`). Les codes « Events seulement »
  (`ConfigReloaded`…) y apparaissent comme advisories tant qu'aucun
  `announce_change` ne les émet (M2+).
- **e2e au M0** : un smoke sans batlehub (`TokenSecretNotAllowed`,
  `InstanceUnreachable`) et la bascule de leader ; le test d'upgrade est
  sauté tant qu'aucun chart n'est publié (première fois à l'alpha du M2 :
  le valider à la main sur une branche avant, 9.3).
- **Pousser des workflows** : `gh repo create --push` pousse avec le jeton
  de `gh`, sans le scope `workflow` : refusé. Le `git push` normal
  (credential `store`) passe.

### Constats du M1 (2026-10-14)

`test:live-batlehub` vert contre l'image `ghcr.io/batlehub/batlehub:1.5.0`
(Postgres à côté, `task batlehub:container:start`, config
`deploy/live/config.toml`) ; l'e2e kind déploie le même couple et attend
une instance external `Ready`. Kit **v0.14.3** (licence du gabarit en
placeholder, constat du M0). Couverture : 90,6 % des lignes, tests live
compris, après le portage des tests binaires de forgejo
(`crates/operator/tests/binary.rs` : HTTPS, lease, reconcile, perte du
lease, SIGTERM ; `crates/crdgen/tests/in_sync.rs`).

- **Image** : `ghcr.io/batlehub/batlehub` (pas `ghcr.io/batleforc/…`) ;
  4.1 est corrigé. La release GitHub v1.5.0 était encore un brouillon,
  l'image et le tag étaient publiés.
- **Client régénéré sur l'OpenAPI 1.5.0** (`task gen:bump`), sans
  nouveau patch.
- **`GET /api/v1/me` avec un token inconnu** : `200` et
  `role: "anonymous"`, jamais `401`. Le contrôle du rôle (déjà au M0) le
  refuse donc en `OperatorUnauthorized` (« role is "anonymous" »), testé
  en contrat et en live.
- **Warnings** : `GET /api/v1/admin/config/warnings` demande
  `config:read` (un `user` reçoit `403`). Une config minimale en donne
  déjà deux (`proxy-trust.unconfigured`, `audit.no-retention`) :
  l'advisory `ConfigWarnings` sera la norme, pas l'exception. Une erreur
  de lecture des warnings fait échouer le reconcile comme `ping`.
- **Config minimale de batlehub** : `[storage]` est obligatoire
  (`missing field storage`), `[[registries]]` non.
- **Forme de `BatleHubLocalInstance` au M1** : `spec.external` est
  **requis**, seul (`url`, `adminTokenSecretRef`, `tls` du kit
  `LocalTlsOptions`). `manageConfig` et `podSelector` arrivent au M2,
  `managed` au M4 : rendre `external` facultatif à ce moment-là (avec la
  règle CEL « exactement un mode ») n'est pas une rupture. Status propre
  (`endpoint`, `version`, `warnings`) ; `version` et `warnings` sont
  gardés tant que l'instance ne répond pas.
- **CA** (`tls.caSecretRef`) : lu sans label de consentement (ce n'est
  pas un secret) ; absent ou sans certificat PEM → `InvalidSpec`.
- **`InstanceInUse`** : publié aussi sur `Ready` pendant que la
  suppression attend (pas seulement en Event), comme le dit 4.1. Aucun
  kind ne se lie encore à une instance : l'adaptateur
  `ClusterDependents` rend une liste vide, l'envtest passe par un faux
  (`FakeDependents`) ; la vraie liste arrive avec `BatleHubRegistry`
  (M2). `force-orphan` testé.
- **Taskfile** : les variables des Taskfiles inclus partagent un seul
  espace (le `ENGINE` d'`e2e.yaml` écrasait celui de `batlehub.yaml`) :
  préfixe `LIVE_`.
- **Bloquant pour le M2** : `batlehub-config` **v1.5.0 ne porte pas
  D4/D8**. Elle a la fusion par couches (`load_layered`,
  `load_layered_from_str`, tableaux fusionnés par identité `name`/`type`),
  mais pas `merge_layers` (fusion sans expansion d'env), ni
  `validate_layers(layers, env)` (l'expansion `${VAR}` et
  `apply_env_overrides()` lisent `std::env` du processus), ni
  `RESTART_KEYS`. Le M2 attend une batlehub qui les publie (v1.5.1 ou
  v1.6.0, à décider côté batlehub). **Levé le 2026-10-15** : v1.6.0
  (RFC 0037).

### Constats du M2 (2026-10-15)

batlehub **v1.6.0** épinglée partout (`task gen:bump` : spec, client,
`batlehub-config` en dépendance git `tag = "v1.6.0"`, image des tests
live et de l'e2e), kit **v0.15.0**. `test:live-batlehub` vert contre
l'image 1.6.0 : passerelle (dry run, stage, apply, relecture, refus) et
controllers sur envtest (config poussée avec une registry, clé à
redémarrage retenue puis rétablie). envtest : config rendue depuis
`spec.config` + une couche ConfigMap + registries (même namespace et
namespace accepté par sélecteur), doublon de nom, `${` d'un autre
namespace, Secret non labellisé (instance et `configFrom`), namespace non
accepté, `InstanceConfigUnmanaged`, `ConfigInvalid`,
`OperatorTokenShadowed`, `RestartForbidden`. e2e kind : batlehub à 2
réplicas, `podSelector` + `manageConfig` + une registry, fichier de
chaque pod relu.

- **Forme de D4 (RFC 0037 de batlehub)** : voir l'historique v2.2. Le
  choix « redémarrage ou non » d'une instance external ne passe pas par
  `classify` mais par le `restart_required` du dry run
  `POST /admin/config/validate` : calculé par l'instance contre ce qu'elle
  a chargé **au démarrage**, couche credentials comprise, il voit aussi
  une clé à redémarrage qu'un reload antérieur (console) a déjà appliquée.
  `classify` sert au managed (M4).
- **Comportement réel du reload** (vérifié en live, conforme au faux
  `FakeGateway`) : `pending/apply` écrit le fichier par renommage
  atomique — **le répertoire** doit être inscriptible, pas seulement le
  fichier ; le watcher voit l'écriture mais ne re-stage rien (empreinte
  identique à la dernière tentative) ; re-stager les mêmes octets répond
  `pending_created: false` (d'où le nonce) ; le dry run de la config en
  place rend des listes vides.
- **Écriture impossible** : si l'instance ne peut pas écrire son fichier,
  `apply` réussit quand même (erreur seulement loguée) : la config est
  chargée en mémoire et perdue au redémarrage. L'opérateur relit le
  fichier après chaque apply : différent → `ConfigReadOnly`. Un
  `is_readonly: true` de `GET /admin/config/content` veut dire hot reload
  désactivé → `HotReloadDisabled`.
- **Chart batlehub** : son fichier vient d'un ConfigMap (lecture seule).
  Pour `manageConfig`, chaque pod doit écrire sa propre copie (l'e2e
  copie le ConfigMap dans un `emptyDir` par un initContainer) ; à noter
  pour l'importeur (M5) et la doc du chart batlehub.
- **Valeur factice** des `${VAR}` à la validation : `https://weebo-batlehub.invalid`
  passe les contrôles d'URL de batlehub (Postgres, S3, issuer OIDC en
  https) ; `PROXY_CACHE__*` et `BATLEHUB_*` répondent « non posée »
  (une valeur factice écraserait le fichier). En external l'opérateur ne
  lit aucune valeur réelle : rien de secret ne peut apparaître dans un
  message du parser.
- **Contrôle du token (6.3)** : sur le document fusionné, une entrée
  `[[auth]] type = "token"` de rôle `admin` dont la `value` est le token
  (en clair, ou un hash Argon2 vérifié, résultat mis en cache par couple
  hash/token) ; une `value` en `${VAR}` est invérifiable et acceptée.
- **Pending d'un tiers** : le `from-content` de l'opérateur remplace tout
  pending existant ; le `DELETE …/pending` de 6.1 (règle 4) n'est pas
  nécessaire (gardé au port pour `configDiscardPending`, M3).
- **Pods** (`podSelector`) : appelés en HTTP clair sur l'IP et le port
  `http` (sinon le premier) ; un seul dry run pour tous, push et approbation
  pod par pod, le refus d'un pod nomme ceux qui ont déjà chargé.
- **Registries** : le contrôleur d'instance rend et écrit le status de
  chaque registry rendue ou écartée ; le contrôleur registry n'écrit que
  ce qu'aucune instance ne rend (instance introuvable, refusée,
  `InstanceConfigUnmanaged`). Pas de finalizer sur `BatleHubRegistry` :
  l'instance re-rend sans elle. Watch : toute registry relance toutes les
  instances (la file les fusionne ; un patch de status identique ne
  produit pas d'événement, pas de boucle) ; les ConfigMaps (métadonnées)
  relancent les instances qui les nomment ; les Secrets à la
  resynchronisation (D9).
- **Webhook** : refuse ce qui est certain et ne dépend que du CR :
  aucune config, `spec.config` qui n'en est pas une (`InvalidSpec`,
  `ConfigInvalid`), et — sans `configLayers` — un `spec.config` que le
  parser refuse ; `NamespaceNotAllowed` sur un `instanceRef`
  explicitement étranger ; un fragment `configFrom` qui n'est pas du TOML.
  Une couche (un ConfigMap se corrige sans toucher au CR) ou la registry
  d'une autre équipe qui casse la config ne bloque jamais les éditions de
  l'instance (6.8 révisé) : le status le dit. Ni le contrôle du token, ni
  les doublons de registries. Le timeout du webhook n'a pas été mesuré.
- **`clusterKinds: false`** : les lectures propres (`clusterRules` :
  ConfigMaps, Namespaces, pods) disparaissent avec le ClusterRole ; les
  watches des ConfigMaps et des Namespaces sont alors sautés, mais une
  couche ConfigMap, un `configFrom` ConfigMap ou un `podSelector` échouent
  en `KubernetesApiError`. Le chart ne peut toujours pas refuser le mode
  (rendu de fumée du kit) : documenté comme partiel (values, guide
  d'installation) ; §11.2 `params.watchRules` reste la solution.
- **Dépendances** : `batlehub-config` tire `batlehub-core` (ammonia, zip…),
  plus lourd que nécessaire (le RFC 0037 l'assume). cargo-deny : quatre
  exceptions de licence par crate (MPL-2.0 de `cssparser`/`dtoa-short`,
  `bzip2-1.0.6`, `CC0-1.0`), toutes autorisées par le `deny.toml` de
  batlehub.
- **Revue du 2026-10-15** (avant l'alpha), corrigée :
  - aucun message ne cite le texte d'une source (une erreur de parse TOML
    cite la ligne fautive, une couche peut venir d'un Secret) : lignes
    citées retirées, message d'erreur JSON de batlehub décodé d'abord ;
  - un placeholder est toujours un placeholder pour la validation, quel
    que soit son nom (`${BATLEHUB_FRONT_URL}` était pris pour un override) ;
  - YAML → TOML en chaînes d'une ligne (un bloc `|` avec `${VAR}` était
    refusé par `merge_layers`) ;
  - `ConfigReadOnly` n'est plus un reload à chaque passe : attendu comme
    un refus (10 min), `status.unpersistedConfigHash` ;
  - pendant l'attente d'un refus : message stable (pas de churn de status
    ni de réveil de toutes les instances), `pods[]` gardés,
    `status.rejectionMessage` ; l'attente ne s'applique qu'à une instance
    en retard, et un succès efface le refus ;
  - ordre du §5 : la config est rendue avant de lire le token et
    d'appeler l'instance ; le status des registries est écrit même quand
    le token est illisible ; registries « rendues, retenues » sous
    `Manual` (advisory `ConfigHeld`) ;
  - noms de registries de l'instance lus dans **toutes** ses couches ; la
    plus ancienne garde son nom même en échec ;
  - contrôle du token dans l'ordre de batlehub (premier provider qui
    connaît le token, valeur en clair d'abord, dernière entrée gagnante) ;
  - un 503 n'est « hot reload désactivé » que si batlehub le dit, un 404
    « rien en attente » idem (un proxy devant répond aussi 503/404) ;
  - watches ajoutés : ConfigMap d'un `configFrom`, labels des Namespaces
    (mode `Selector`) ; `ClusterDependents` et la suppression suivent le
    sélecteur de labels de l'opérateur ; plus de double Event `Warning`
    pendant `InstanceInUse` ;
  - port d'un pod : celui nommé `http`, sinon le premier du premier
    conteneur (jamais un sidecar) ; le `podSelector` doit exclure les pods
    worker du chart (`app.kubernetes.io/component: worker`) ;
  - e2e : `helm show chart --devel` (sinon une alpha publiée n'est jamais
    l'ancienne version du test d'upgrade), et le test d'upgrade efface les
    conditions des CR puis attend que le **nouvel** opérateur les
    réécrive.
- **Release de l'alpha** : `publish.yml` du kit v0.15.0 échoue sur un
  dépôt sans tag final `vX.Y.Z` (il cherche le plus haut pour décider de
  `latest`) et publie la release GitHub sans `--prerelease` : corrigé
  dans le kit (release suivante), dont `publish.yml` est épinglé ici.
- **Reste du M2** : la release **0.1.0-alpha.1** (D7) et le test
  d'upgrade, qui ne tourne vraiment que sur un tag.

## 11. Évolutions proposées

### 11.1 Côté batlehub (nous le maintenons aussi)

Les deux premières lignes étaient **requises avant le M2** (D4, D8),
livrées par batlehub v1.6.0 ; les autres sont facultatives, chacune
retire du code subtil de l'opérateur.

| Évolution | Statut | Retire |
| --- | --- | --- |
| `batlehub_config::merge_layers(&[&str]) -> toml::Value` (fusion sans expansion d'env) et `validate_layers(&[&str], env: impl Fn(&str) -> Option<String>)`, où `env` sert **aussi** aux overrides `PROXY_CACHE__*` (aujourd'hui `apply_env_overrides()` lit `std::env`, 2.2) | **livré en v1.6.0** (RFC 0037) : `merge_layers` rend un document canonique (`String`), `validate_layers(layers, &dyn Fn)` | Toute substitution maison, et le risque de diverger sur la fusion (2.2, 2.3) |
| `batlehub_config::RESTART_KEYS` (la liste utilisée par batlehub lui-même) | **livré en v1.6.0** sous forme d'allowlist `reload_keys::RELOAD_KEYS` + `classify`, et dans le `ReloadDiff` du dry run (`restart_required`) | Toute copie de la liste (2.4) |
| `POST /admin/config/reload` avec `{"expected_sha256": …}` : recharge si le fichier a ce hash, répond le hash chargé ; pas de dédoublonnage sur un hash attendu | facultatif (si 6.1 est fragile au M2) | Le nonce de re-stage (6.1), et le risque d'approuver une révision qui n'est pas celle attendue |
| `GET /admin/config/content` renvoie aussi le SHA-256 des couches lues | facultatif | La comparaison d'octets par pod |
| Propagation d'un reload approuvé entre réplicas (via le backend de cache partagé) | facultatif | L'approbation pod par pod par IP (2.9), `podSelector` (6.6) |

**Actions côté batlehub (faites, v1.6.0)** :

1. `merge_layers`, `validate_layers(layers, env)` et `reload_keys`
   (au lieu de `RESTART_KEYS`) dans `crates/config` de batlehub, avec
   leurs tests (son RFC 0037) ;
2. le tag v1.6.0 (D8 révisée) ;
3. `batlehub-config` (`tag = "v1.6.0"`) et `spec/batlehub-v1.6.0.json`
   épinglés dans weebo-batlehub (`task gen:bump`).

### 11.2 Côté kit

- `Instances<I, L>` sans kind cluster-scoped (aujourd'hui `I` est
  obligatoire) : en attendant, l'opérateur implémente
  `InstanceDirectory` sur ses instances locales (2.8). Utile à tout
  opérateur dont le produit n'a qu'une forme namespacée.
- Règles propres pour le Role `-watch` (un `params.watchRules` à côté de
  `params.clusterRules`) : sans lui, `watch.namespace` laisse les règles
  du workload dans le ClusterRole et `clusterKinds: false` reste partiel
  sans que le chart puisse le refuser (7.1).
- Avertissements dans `Admission` (`warnings` de l'`AdmissionResponse`) :
  changement du trait, donc release mineure du kit.
- Index « Secret/ConfigMap → CR qui le lisent » en watch de métadonnées
  (6.7) : forgejo et authentik relisent leurs Secrets à chaque reconcile,
  ils n'en ont pas l'usage aujourd'hui.

## 12. Hors périmètre

- Postgres, S3, Redis, fournisseurs OIDC, Trivy : prérequis vers lesquels
  la config pointe.
- Backup/restore : batlehub n'a pas d'endpoint.
- Ingress dérivé des `hosts` des registries (voir 4.1).
- `watch.clusterKinds: false` (tout en Roles), tant que le kit n'a pas de
  règles propres pour le Role `-watch` (7.1, §11.2).
- Un `BatleHubInstance` cluster-scoped (D5).

**Plus tard** (après la 0.1.0) :

- Actions bulk (`/admin/registries/{r}/bulk/*` : yank, deprecate, unlist,
  owners, visibility) et namespace claims, en actions de maintenance avec
  un sélecteur `packages[]` + plage de versions.
- Nouveaux kinds : `BatleHubAuthProvider`, namespace claims, clés de
  signature.
- `v1beta1` et webhook de conversion.
- Miroir Forgejo/Harbor de l'image (porte de scan propre), en plus de
  `publish.yml` du kit.
- Plugin `kubectl batlehub` sur `api` + `batlehub-client` (ex.
  `kubectl batlehub warm hub npm typescript` crée la maintenance et
  attend).

## 13. Points d'attention

- **La fusion et la validation** viennent de `batlehub-config`, jamais
  d'une copie : sinon les hashs et la détection du masquage du token sont
  faux.
- **Le protocole de reload** (6.1) est le comportement le plus subtil ;
  la liste de cas limites du §9.1 est son jeu de tests d'acceptation, en
  use case puis en live.
- **Au plus une fois** pour les maintenances, et **jamais de boucle
  d'erreur** sur un refus : deux propriétés faciles à perdre avec un
  framework qui retente par défaut — un refus est un `Outcome`, pas une
  `Error`.
- **Rien de batlehub dans le kit** : ce qui paraît générique (annuaire
  d'instances sans kind cluster, index de ConfigMaps) reste dans
  l'opérateur jusqu'à ce qu'un second opérateur en ait besoin ; tout ce
  que le kit fournit déjà (résolution et liaison d'instance, lecture des
  tokens à opt-in, scope, CI et release) est pris tel quel.
- **Aucun Secret ne sort sans opt-in** (2.11) : un nouveau champ qui
  référence un Secret dont le contenu part chez batlehub passe par le
  label `credential`, sinon c'est la faille corrigée dans forgejo.
- **Le status d'abord** : tout ce qui est écrit côté batlehub est
  enregistré dès l'écriture réussie, et relu depuis l'apiserver avant de
  conclure à un conflit (4, 4.4).
