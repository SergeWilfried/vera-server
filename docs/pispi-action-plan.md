# Plan d'action PI-SPI — VeraWall

Synthèse actionnable des décisions marché & business de la session. À suivre en
cochant les cases. Priorités : **P0** = bloquant / immédiat · **P1** = important ·
**P2** = à programmer.

Documents liés : [`pispi-target-list.md`](pispi-target-list.md) (cibles) ·
kit commercial dans `~/Downloads` (pitch client, pitch partenaire, synthèse Excel,
doc technique & sécurité).

---

## Les décisions cadres (rappel)

- **Le créneau** : la responsabilité anti-fraude côté client (auth, arnaque APP) revient au **participant initiateur**, pas au commutateur BCEAO. C'est exactement ce que VeraWall outille — un point aveugle structurel de la plateforme.
- **La fenêtre** : PI-SPI est live depuis avril 2026 ; la fraude APP monte 12-24 mois après (UK/Pix/UPI) → **surge attendue mi-2027 → 2028**. Objectif 2026 : références + données, pas le CA.
- **Le wedge** : la **bannière anti-arnaque embarquée** — 100 % sur l'appareil, intégrable en quelques jours, sans dépendance PI-SPI, en mode observation. Puis extension vers le scoring complet (bascule back-end, pas de nouvelle intégration).
- **Le canal** : les intégrateurs (SI) sont hors de portée maintenant → **vente directe** aux participants. Les **EME (Orange en tête)** sont les meilleures premières cibles.
- **Priorisation** : Orange → autres EME → groupes bancaires (Coris/Orabank/Ecobank/BOA/UBA) → groupes IMF (COFINA/Baobab) → banques nationales.
- **Tarification** : par **MAU** (par paliers), wedge peu cher, logique *land & expand* ; ne pas facturer à la transaction (rails mobile money à faible valeur).

---

## P0 — Priorités immédiates (4 prochaines semaines)

### Readiness pilote (technique — bloquant pour toute démo bancaire crédible)
- [ ] **[P0]** Redéployer le collecteur (Render) avec le code de la session — tout le scoring récent (vélocité/anti-drain, seuils par devise, scoring step-up, intervention `SCAM_WARNING`) n'est **pas encore en production**.
- [ ] **[P0]** Tester la détection d'appel iOS (`CXCallObserver`) sur un **appareil physique** — jamais validé (le simulateur ne passe pas d'appels). C'est le signal phare : il doit être irréprochable.
- [ ] **[P1]** QA de détection sur un panel d'OEM/versions Android réels (le bug `requireOptionalNativeModule` qui rendait la détection muette a été corrigé — vérifier sur device).
- [ ] **[P2]** Traiter les 2 alertes Dependabot du dépôt `vera-server`.

### Commercial (amorçage)
- [ ] **[P0]** Identifier la voie d'entrée vers **Orange** (Orange Money / Finances Mobiles / Orange Bank Africa) — intro chaude, équipe paiements/risque. Cible n°1.
- [ ] **[P1]** Lister 2-3 EME/participants « warm » atteignables (MTN CI, Axian/Mixx, Moov, Touchpoint) et le bon interlocuteur (risque/fraude, pas achats).
- [ ] **[P1]** Préparer un **one-pager de prise de contact** (extrait du pitch client) + une démo courte (bannière + verdict) sur device.

### Conformité (débloquer la revue SSI d'une banque)
- [ ] **[P0]** Renseigner les mentions **« À confirmer par VeraWall »** du doc technique : région d'hébergement, résidence des données, sous-traitants, conservation.
- [ ] **[P1]** Préparer un **modèle de DPA** (accord de traitement des données) et une **AIPD** type, alignés BCEAO / autorité nationale.
- [ ] **[P2]** Définir la position sur les certifications (ISO 27001 / SOC 2) : détenues, en cours, ou feuille de route — ne jamais surévaluer dans un document remis à une SSI.

---

## Phase 1 — Amorçage commercial (T3 2026)

- [ ] **[P0]** Signer **1 à 2 partenaires pilotes** (idéalement 1 EME) sur le wedge bannière, en mode observation.
- [ ] **[P1]** Cadrer chaque pilote : parcours à risque prioritaires, périmètre, seuils XOF, critères de succès chiffrés.
- [ ] **[P1]** Déployer la bannière + le scoring en **shadow** ; calibrer les seuils par devise et la vélocité sur le portefeuille réel du partenaire.
- [ ] **[P2]** Instrumenter la mesure d'impact (ce qui aurait été retenu, valeur des pertes évitées) pour le bilan de pilote.
- [ ] **[P2]** Engager **tôt** un groupe multi-pays à cycle long (Ecobank ou un groupe panafricain) — commencer parce que c'est lent.

## Phase 2 — Montée en charge (T4 2026 → 2027)

- [ ] **[P1]** Convertir les pilotes de l'observation vers **l'activation** (STEP-UP / HOLD) sur seuils maîtrisés par le client.
- [ ] **[P1]** Décliner via les **groupes** : une relation Orange/Coris/Ecobank = plusieurs pays (effet de réplication).
- [ ] **[P2]** Attaquer le segment **IMF** via COFINA + Baobab avec les **détecteurs côté registre** (fraude commission agent, mules) — sans SDK.
- [ ] **[P2]** Réévaluer le **canal intégrateur** une fois une référence acquise (les SI portent un produit prouvé, pas un produit à évangéliser).
- [ ] **[P2]** Explorer la piste **Mojaloop / PISP** : si PI-SPI est bien Mojaloop, viser une intégration au niveau plateforme = distribution multi-pays (vente longue et politique — à traiter comme ambition, pas comme wedge).

---

## Chantier produit & plateforme (readiness & différenciation)

- [ ] **[P1]** Résoudre la divergence moteurs Go/Node (revue de code) : 5 signaux présents côté Go absents côté Node (`REMOTE_ACCESS`, `HEADLESS_BROWSER`, `MOUSE_ANOMALY`, `IMPOSSIBLE_TRAVEL`, `MOCK_LOCATION`) + ordre des signaux ; corriger le commentaire « faithful port » obsolète.
- [ ] **[P2]** Détection screenshot iOS/hardware réelle (au-delà de l'émulateur), et évaluer `expo-screen-capture` pour les screenshots (déjà en place pour la prévention).
- [ ] **[P2]** Ajuster les montants de la démo pour XOF (le scénario « Coached » retombe en STEP-UP au lieu de HOLD sous le seuil 500 000 XOF) — cohérence de la démo commerciale.
- [ ] **[P2]** Boucler le SDK iOS (module natif d'appel livré ; valider en build device EAS).

## Collatéral & marque (largement fait — finitions)

- [ ] **[P1]** Renseigner les placeholders des livrables : `[Nom de l'établissement]`, coordonnées de contact, date/version du doc technique.
- [ ] **[P2]** Version **anglaise** du doc technique et du pitch client (marchés anglophones / Mojaloop).
- [ ] **[P2]** Guide d'intégration détaillé (schémas de charge utile, exemples d'appels d'API) pour les équipes techniques des participants.

---

## Suivi

- Cibles & statut d'approche : voir [`pispi-target-list.md`](pispi-target-list.md).
- Mettre à jour ce plan à chaque jalon (pilote signé, collecteur redéployé, test iOS validé).
