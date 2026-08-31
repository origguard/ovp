# Témoin — marche à suivre

Un fichier, aucune dépendance, Node 18 ou plus. Cinq minutes.

## 1. Initialiser (une seule fois)

```bash
node witness.mjs --init --log https://origguard.com/api/v1 --name "Ton nom ou ton organisation"
```

Le script affiche **ta clé publique** : envoie-la à l'opérateur. Il crée aussi `witness-state.json`, qui contient **ta clé privée** — ne le partage pas, ne le versionne pas.

## 2. Faire tourner régulièrement

```bash
node witness.mjs --log https://origguard.com/api/v1
```

Une fois par jour suffit. Exemple avec cron :

```
0 9 * * *  cd /chemin/vers/temoin && /usr/bin/node witness.mjs >> witness.log 2>&1
```

Chaque exécution produit `cosignature.json`, à transmettre à l'opérateur (ou à publier toi-même).

## 3. Ce que le script vérifie avant de signer

| Situation | Comportement |
|---|---|
| Signature du journal invalide | **refuse** |
| Clé du journal différente de celle épinglée | **refuse** — une rotation non annoncée est indiscernable d'une substitution |
| Taille de l'arbre en diminution | **refuse** — des entrées ont disparu |
| Taille identique, racine différente | **refuse** — l'historique a été réécrit |
| Arbre agrandi sans preuve de consistance valide | **refuse** |
| Tout est cohérent | cosigne, et met à jour ton état |

En cas de refus, **l'état n'est pas mis à jour** : tu restes sur le dernier état que tu avais validé. Le code de sortie vaut `1`, utilisable pour déclencher une alerte.

## 4. La première exécution

Elle cosigne, mais n'établit aucune continuité — il n'y a rien à comparer. Le script le dit explicitement. La détection commence à la deuxième observation.

## 5. Ce que ta signature dit exactement

> J'ai observé cette tête d'arbre à cette date, et elle était cohérente avec celle que j'avais vue précédemment.

Elle ne dit rien du contenu du journal, ni du produit de l'opérateur, ni de leur qualité. Si l'opérateur présente ta cosignature comme une caution de son produit, il ment — et tu peux le lui dire publiquement.

## 6. Arrêter

Supprime la tâche cron. Préviens l'opérateur pour qu'il retire ton nom de la page publique. Aucune démarche, aucun préavis.
