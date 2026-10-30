# internal-auth-utils (paquet de démonstration)

Ce paquet n'est **pas** une vraie bibliothèque. Il constitue le côté « attaquant »
du laboratoire de confusion de dépendances. Son seul but est de rendre le
mécanisme d'exécution de code à l'installation **observable**, dans un cadre
strictement local et inoffensif.

## Rôle dans le laboratoire

- **Nom** : `internal-auth-utils`, choisi pour ressembler à une bibliothèque
  interne d'entreprise dont une application pourrait dépendre.
- **Version** : `99.0.0`, volontairement démesurée afin de battre n'importe quelle
  version interne légitime (par exemple `1.4.2`) lors de la résolution. C'est le
  cœur de la confusion de dépendances : le résolveur retient la version la plus
  élevée qu'il peut voir parmi tous les index configurés.
- **Charge utile** : un *hook* de télémétrie inoffensif (`_telemetry.py`) qui
  collecte uniquement des métadonnées non sensibles et les envoie en HTTP POST
  vers `http://127.0.0.1:8888/collect`.

## Les trois moments d'exécution

La charge utile s'exécute à trois instants, ce qui illustre la surface
d'exécution réelle d'un paquet :

| Moment | Déclencheur | Code concerné |
|---|---|---|
| `build` | Construction de la distribution | Commande `build_py` de `setup.py` |
| `post-install` | Installation depuis les sources | Commande `install` personnalisée de `setup.py` |
| `import` | Premier import du module | Effet de bord dans `__init__.py` |

Chaque exécution envoie une balise de métadonnées au superviseur local, si bien
qu'une unique ligne de dépendance négligente produit plusieurs exécutions
distinctes.

## Garanties de non-nocivité

La charge utile est volontairement limitée. Elle ne collecte que le nom d'hôte, le
nom d'utilisateur, la version de Python, la plateforme et le répertoire courant.
Elle ne lit aucun secret, ne touche jamais au fichier `.env` de l'application
cible, ne contacte jamais Internet (la destination est épinglée sur la boucle
locale) et échoue silencieusement si le superviseur est absent, comme le ferait un
code réel pour ne pas interrompre l'installation. Le test
`tests/test_demo_package_is_benign.py` vérifie en continu que le code source ne
référence aucun chemin sensible.

## Construction

Pour que les hooks s'exécutent à l'installation, le paquet est distribué sous
forme de **sdist** (installation depuis les sources) :

```bash
python -m build --sdist .      # produit dist/internal_auth_utils-99.0.0.tar.gz
```

L'artefact ne doit ensuite être déposé que sur le **registre local** du
laboratoire (voir `../../scripts/publish_package.sh`). Il ne doit jamais, en aucune
circonstance, être téléversé vers un registre public.
