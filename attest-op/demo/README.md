# Démonstration

Ce dossier ne contient **aucune clé**. Génère la tienne :

```bash
node ../bin/ogattest.mjs keygen > cles.json      # ne JAMAIS versionner ce fichier
node ../bin/ogattest.mjs attest --in original.pdf --out caviarde.pdf --keys cles.json \
     --product "Mon outil" --version 1.0.0 > caviarde.pdf.ogatt.json
node ../bin/ogattest.mjs verify --file caviarde.pdf --att caviarde.pdf.ogatt.json \
     --key "$(python3 -c "import json;print(json.load(open('cles.json'))['publicKey'])")"
```

`rate.pdf` est un caviardage volontairement raté : `attest` doit **refuser** de le signer.
