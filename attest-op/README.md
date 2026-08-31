# attest-op — prouver une opération locale sans divulguer la donnée

Un tiers reçoit **uniquement le fichier de sortie**. Il peut alors vérifier que la transformation annoncée a réellement eu lieu, que le fichier n'a pas bougé, et par quel logiciel il a été produit.

**Sans jamais voir le document d'origine.**

---

## Le problème réputé insoluble

> « On ne peut pas prouver qu'une donnée n'est jamais sortie de l'appareil. »

C'est exact : c'est une preuve d'absence, portant sur un futur ouvert, sur une machine qu'on ne contrôle pas. Aucun mécanisme ne l'établit.

**On ne l'établit donc pas.** On établit trois présences dont l'absence découle :

| On prouve | Par quoi |
|---|---|
| L'impossibilité est **mécanique** | CSP `connect-src 'none'` à l'intérieur de l'artefact haché — le navigateur bloque |
| Le binaire est **identifié** | empreinte du build, signée, publiée en journal append-only |
| Le résultat est **revérifiable** | les propriétés se rejouent sur la sortie seule |

Aucun théorème n'est brisé. Une question insoluble est remplacée par trois questions solubles.

## Le principe qui fait toute la différence

**Les propriétés sont rejouées, jamais crues sur parole.**

Une attestation dont la signature est parfaitement valide est **rejetée** si la propriété annoncée est infirmée au contrôle. La signature prouve l'intégrité de la déclaration, pas sa véracité. Le vérificateur, lui, recalcule.

C'est ce qui distingue ce format d'un simple certificat.

## Utilisation

```bash
# 1. Une fois : la paire de clés du producteur
node bin/ogattest.mjs keygen > cles.json

# 2. Après chaque opération, sur le poste de l'utilisateur
node bin/ogattest.mjs attest \
  --in original.pdf --out caviarde.pdf --keys cles.json \
  --product "Toolocal Caviardage" --version 1.4.0 \
  --artifact <sha256-du-build> --log https://origguard.com/log/tc-1.4.0 \
  > caviarde.pdf.ogatt.json

# 3. Par le destinataire — l'original n'est PAS requis
node bin/ogattest.mjs verify \
  --file caviarde.pdf --att caviarde.pdf.ogatt.json --key <cle-publique>
```

`attest` **refuse de signer** si une propriété échoue : attester une opération non conforme reviendrait à produire une fausse déclaration.

## Ce que le rapport dit — et ne dit pas

Le vérificateur produit trois sections. La troisième est la plus importante :

```
ÉTABLI
  ✓ La signature est valide
  ✓ La clé figure parmi les émetteurs approuvés
  ✓ Le fichier fourni est exactement celui décrit par l'attestation
  ✓ Propriété « no-incremental-revisions » REJOUÉE et confirmée : 1 révision

NON ÉTABLI — à ne pas confondre avec un échec
  · Que le fichier d'ENTRÉE était bien le document qu'on prétend
  · Que le build figure au journal public : à contrôler sur <url>
  · Que la machine n'était pas compromise
```

Une preuve dont on ignore les limites produit de la surconfiance — et la surconfiance vaut moins que pas de preuve du tout. Ces limites sont énoncées à **chaque** vérification, y compris quand tout est conforme.

## Propriétés vérifiables incluses (PDF)

Chacune correspond à un échec de caviardage réellement survenu :

| Propriété | Ce qu'elle attrape |
|---|---|
| `no-incremental-revisions` | rectangles noirs + enregistrement incrémental : **l'original est encore dans le fichier** |
| `no-embedded-files` | une pièce jointe contenant le document entier |
| `no-javascript` | du script capable de reconstituer ou d'exfiltrer à l'ouverture |
| `absenceOfTerms` | termes toujours présents en clair (à n'utiliser que si le vérificateur les connaît légitimement — **jamais dans l'attestation**, qui circule) |

Ajouter une propriété = une fonction qui prend les octets de la sortie et renvoie `{ id, claim, method, result, measured, recheckable }`.

## Cryptographie

Ed25519 via WebCrypto (Node 18+, navigateurs, WebViews) sur une sérialisation **canonique** — clés triées récursivement. Sans forme canonique, deux représentations du même objet produisent deux signatures différentes et la vérification échoue sans qu'aucune fraude n'ait eu lieu.

Le vérificateur peut donc tourner dans une page hors-ligne, sans installation.

## Limites, à connaître avant toute annonce

- **L'entrée n'est pas prouvée** — seule son empreinte est enregistrée. Elle permet de prouver le lien *si* l'entrée est un jour produite.
- **Une machine compromise défait tout** — vrai de toute cryptographie.
- **Seules les propriétés contrôlables sur la sortie** sont revérifiables. Les autres restent des déclarations, et le rapport le dit.
- **Le journal public reste à construire.** Tant qu'il n'existe pas, `build.logEntry` est une promesse, pas une preuve.

## Tests

```bash
npm test     # 22 vérifications
```

Couvre : vérification sans l'entrée, rejeu des propriétés, refus d'attester un échec, détection d'altération et de substitution, énoncé systématique des limites, échecs réels de caviardage, indépendance à l'ordre des clés.

---

*© 2026 ORIGGUARD · Forges Emmanuel · admin@origguard.com*
