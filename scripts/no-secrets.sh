#!/usr/bin/env bash
# Refuse toute MATIÈRE de clé privée hors des vecteurs de test.
#
# On ne cherche pas le mot « privateKey » : c'est un nom de paramètre parfaitement
# légitime, présent dans tout le code. On cherche une AFFECTATION portant une
# valeur assez longue pour être une vraie clé, ou un en-tête PEM.
#
# Un contrôle qui produit des faux positifs est désactivé dans la semaine —
# ce qui est pire que pas de contrôle du tout.
set -u

PEM='BEGIN [A-Z ]*PRIVATE KEY'
ASSIGN='("(private|secret)Key"|(private|secret)Key)[[:space:]]*[:=][[:space:]]*"[A-Za-z0-9+/_-]{40,}'

HITS=$(grep -rlE "$PEM|$ASSIGN" . \
        --exclude-dir=node_modules --exclude-dir=.git \
        --exclude-dir=scripts --exclude-dir=.github 2>/dev/null \
       | grep -v '^\./SPEC/test-vectors\.json$' || true)

if [ -n "$HITS" ]; then
  echo "MATIÈRE DE CLÉ PRIVÉE détectée hors des vecteurs de test :"
  echo "$HITS" | sed 's/^/  /'
  echo
  echo "SPEC/test-vectors.json contient une clé de démonstration volontairement"
  echo "publiée (Ed25519 est déterministe : sans elle, aucune implémentation tierce"
  echo "ne peut prouver sa conformité). Tout le reste est une fuite."
  exit 1
fi
echo "Aucune matière de clé privée hors des vecteurs de test."
