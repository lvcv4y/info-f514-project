# Projet INFO-F514

Ce dépôt est une implémentation du système ABBOVE imaginé par Rausch et. al., décrit dans [cet article](https://eprint.iacr.org/2025/841.pdf). 

## But

Le but est de reproduire le plus fidèlement le système décrit dans l'article, pour permettre dans un premier temps son étude empirique, puis approfondir les résultats, voire trouver des pistes d'amélioration.

## Structure

L'arborescence se veut la plus proche de la description de l'article. On retrouve donc :
  - `authorities.py` : les autorités de confiance (PKI, organisateur de l'élection) ;
  - `board.py` : le *Bulletin Board* ;
  - `crypto.py` : les méthodes de cryptographie ;
  - `judge.py` : les méthodes du *judge* (détermine si l'élection se déroule correctement ou non) ;
  - `network.py` : le réseau, indigne de confiance ;
  - `tailler.py` : le dépouillement ; 
  - `vote.py` : les votants ;

## Implémentation

Cette première implémentation utilise un réseau et des échanges synchrones. Tout s'exécute dans un unique *thread*. Bien que cela soit assez peu réaliste, cela évite les bugs liés au multithreading (race conditions,...) (qui sont des erreurs de programmation / d'implémentation, et non des vulnérabilités du système cryptographique), en plus d'être assez fidèle à la modélisation par machines du Turing donné dans l'article.