# Déroulé de la résolution de dépendances, pas à pas

Ce document est le cœur conceptuel du laboratoire. Il se lit en parallèle du
fichier [`pyproject.toml`](pyproject.toml).

## Modèle mental : comment un résolveur choisit une version

Un résolveur de dépendances doit répondre à une question : *pour le nom
`internal-auth-utils`, quelle distribution installer ?* Il procède ainsi :

1. Il rassemble l'**ensemble des index configurés** (ici l'index privé local sur
   `127.0.0.1:8080`, plus PyPI déclaré comme index supplémentaire).
2. Il demande à chaque index les **versions disponibles** pour ce nom.
3. Il choisit une version selon sa **stratégie d'index** :
   - `first-index` (valeur par défaut de `uv`, plus sûre) : n'utiliser que le
     **premier index** qui liste le nom. Si l'index privé le possède, PyPI n'est
     jamais consulté.
   - `unsafe-best-match` (ce que cette application active, comportement proche de
     `pip`) : fusionner les versions de **tous** les index et retenir la **plus
     élevée** parmi les versions compatibles.

La confusion de dépendances se niche à l'étape 3. Dès lors que le résolveur
fusionne les index et retient la version la plus élevée, il suffit à un attaquant
de publier une **version supérieure sous le même nom** sur *n'importe quel* index
de confiance.

## Transposition locale de l'attaque

Dans l'attaque réelle de 2021, le sens était le suivant :

```text
index privé :  internal-auth-utils == 1.4.2   (la vraie bibliothèque)
PyPI public :  internal-auth-utils == 99.0.0   (l'imposteur de l'attaquant)  -> gagne
```

Il est hors de question de publier quoi que ce soit sur le PyPI public ; le
laboratoire reproduit donc le même mécanisme en local :

```text
registre local (:8080) :  internal-auth-utils == 99.0.0  (imposteur)  -> gagne
PyPI public :             internal-auth-utils  (absent)
```

Dans les deux cas, le résolveur installe la version **99.0.0**, l'imposteur, car
c'est la version la plus élevée qu'il peut voir parmi les index de confiance.

## Trace d'exécution d'une synchronisation `uv sync`

1. `uv` lit `pyproject.toml` et repère la dépendance `internal-auth-utils`.
2. Il interroge l'index primaire (`:8080/simple/internal-auth-utils/`) et l'index
   supplémentaire (PyPI). L'index local renvoie la version **99.0.0**.
3. Comme `index-strategy = "unsafe-best-match"`, `uv` sélectionne **99.0.0**.
4. `uv` télécharge la **sdist** `internal_auth_utils-99.0.0.tar.gz`.
5. Pour l'installer, il la construit : il exécute le *build backend* du paquet,
   donc `setup.py`. La commande `build_py` personnalisée déclenche le hook de
   télémétrie (**étape « build »**).
6. `uv` installe le paquet. Lors d'une installation depuis les sources, la
   commande `install` personnalisée se déclenche également (**étape
   « post-install »**).
7. Plus tard, lorsque `main.py` exécute `import internal_auth_utils`, le hook à
   l'import se déclenche (**étape « import »**).

Chacune de ces étapes envoie une balise de métadonnées inoffensive au superviseur
local sur `:8888` : on observe ainsi trois événements sur la timeline pour une
seule ligne de dépendance négligente.

## Pourquoi l'impact est si fort

Le développeur n'a jamais tapé de nom malveillant, n'a cliqué sur rien et n'a vu
aucun avertissement. Une seule ligne dans `pyproject.toml`, combinée à une
configuration d'index trop permissive, a suffi à exécuter du code attaquant sur la
machine de build, sur le *runner* de CI et sur chaque poste de développeur ayant
lancé la synchronisation.
