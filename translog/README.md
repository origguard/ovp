# translog — journal public append-only

La pièce qui transforme une attestation en preuve. Sans elle, `build.logEntry` pointe vers une promesse.

Arbre de Merkle **RFC 6962**, publiable en fichiers statiques : n'importe qui peut recopier le journal entier et le recalculer. **Un journal que personne ne peut recopier n'est pas un journal public.**

---

## Ce qu'il garantit, et par quel mécanisme

| Garantie | Mécanisme |
|---|---|
| Une entrée est bien dans le journal | preuve d'inclusion, `log₂(n)` empreintes |
| L'historique n'a pas été réécrit | preuve de consistance entre deux têtes d'arbre |
| La tête d'arbre vient bien du journal | signature Ed25519 |
| L'opérateur lui-même ne peut pas tricher | **le moniteur côté client** |

La dernière ligne est la seule qui compte vraiment, et c'est la plus mal comprise.

## Pourquoi une signature ne suffit pas

Une tête d'arbre parfaitement signée peut décrire un historique falsifié : l'opérateur détient la clé, il resigne ce qu'il veut.

**Ce qui rend la fraude détectable, c'est de conserver la dernière tête vue** et d'exiger, à chaque consultation suivante, une preuve de consistance depuis celle-ci. C'est le rôle du moniteur.

Démontré dans les tests : une entrée est modifiée, l'opérateur resigne, la signature est valide — et le moniteur **rejette** :

```
REJETÉ — taille 1
  ✗ RÉÉCRITURE : même taille, racine différente. L'historique a été modifié.
```

## Utilisation

```bash
node bin/oglog.mjs keygen > log-keys.json
node bin/oglog.mjs init   --dir ./journal --id origguard-builds --keys log-keys.json

# après que delivery-gate a validé un build
node bin/oglog.mjs append --dir ./journal --keys log-keys.json \
     --product "Toolocal Caviardage" --version 1.4.0 \
     --artifact <sha256-de-l-artefact> --checks "local-guard-strict,delivery-gate"

node bin/oglog.mjs prove  --dir ./journal --index 0     # preuve d'inclusion
node bin/oglog.mjs audit  --dir ./journal --state moniteur.json --key <cle-publique>
```

`audit` conserve son état dans `moniteur.json`. **C'est ce fichier qui protège** : sans lui, chaque consultation repart de zéro et ne détecte rien.

## La boucle complète

```
delivery-gate  →  empreinte de l'artefact + contrôles passés
      ↓
translog       →  inscription publique, append-only, cosignable
      ↓
attest-op      →  la sortie porte son attestation, qui référence l'entrée du journal
      ↓
tribunal       →  vérifie la sortie, rejoue les propriétés, contrôle le journal
                  SANS jamais voir le document d'origine
```

## Les limites — affichées à chaque audit, jamais en option

- **Vue divisée.** Un opérateur peut servir deux historiques à deux personnes. Seule la cosignature par des **témoins indépendants** rend cela impraticable : la fraude exigerait la complicité de tous. `addWitness()` est prévu pour ça.
- **La détection commence à la première consultation.** Ce qui précède n'est pas couvert.
- **Le journal atteste qu'une chose a été inscrite, pas que son contenu soit vrai.** C'est `attest-op` qui rejoue les propriétés.
- **Sans témoins, la confiance repose sur l'opérateur.** À dire tant que le réseau de témoins n'existe pas.

## Tests

```bash
npm test     # 17 vérifications
```

Plus une validation exhaustive du cœur Merkle : **1 122 preuves** d'inclusion et de consistance, toutes tailles d'arbre de 1 à 33, tous indices, zéro échec.

Couvre : inclusion, recalcul intégral par un tiers, réécriture détectée malgré signature valide, régression, substitution à taille égale, cosignature de témoin, clé non approuvée.

---

*© 2026 ORIGGUARD · Forges Emmanuel · admin@origguard.com*
