��    �      �  �   L	      `  -   a  ,   �     �  .   �     �       )        9     @     F     N     R     Z     b     j     n     u     x  �               *   *  3   U      �     �  
   �     �  !   �     �  
   �     �     �                 h   *     �     �     �     �     �     �            	             1     H     Y  &   s     �     �     �  @   �                    *     :     B     P     \  
   l  	   w  
   �  
   �     �     �     �  �  �     �     �      �     �  
   �     �  �   �  �   �     =     S     \     i  /   w     �  $   �     �     �     
  !     $   5     Z     l     t     �     �     �     �     �     �     �     �        #   #     G     V     d     v  
   �     �     �     �  "   �     �            D   1     v  
   {  <   �  �   �  E   k     �     �     �     �        6        I     M  c   `  Y   �  	     :   (  #   c     �  	   �     �     �     �     �     �     �  #        /     L     S  �  k  1   L  0   ~     �  *   �  
   �     �  '         0      8      >      F   	   J      T      \      d      h      o      r   �   {      !     #!  :   =!  F   x!  %   �!     �!  
   �!     �!  1   �!     /"     8"     N"     U"     ]"  	   t"     ~"  �   �"  	   :#     D#     c#     ~#  )   �#  7   �#     �#      $     	$  #   $  (   >$     g$  &   |$  A   �$  &   �$     %     %  d   %     �%     �%     �%     �%     �%     �%     �%     �%     &     '&     6&     D&     U&     u&     z&  �  �&     $*     D*  +   ]*  (   �*     �*     �*  �   �*  �   �+  %   O,  
   u,     �,     �,  @   �,     �,  6   �,  $   -  $   D-     i-  -   w-  2   �-     �-     �-     �-     .      .  
   6.  #   A.     e.     }.  
   �.  "   �.  %   �.  4   �.     /     (/     >/  &   Y/     �/     �/     �/  /   �/  5   �/  &   %0     L0  '   k0  m   �0     1     1  N    1  �   o1  \   P2  )   �2  #   �2     �2     3     !3  ;   83  
   t3     3  �   �3     4     �4  E   �4  2   �4     /5     85  (   N5     w5  '   �5     �5  #   �5     �5  4   6  (   I6     r6  (   6         _   1   �   �   �   ^   0                  k   �       �       5       T       o   +                     h   }      �   d   *       R              !   #       4   a            $   I   ?      w   Q      `   u          P   D   ,   M   {      r       S   �       X         V          :      &   i   G   |       K       �   =   	   W   C   L       l       �       '              p           9       3         m   �   z   q   Z   �   /   c   )       6      B   8   J           "               O   (       H   �      ;   7   %   .   -       f      U   t   �   �       >      @   �   n       y   �                         �   e   �   E   <   ~   2   j       s   v       Y      \   F   
   [   �          ]                         b   x   g   N   A   �        "Clear" not available for this storage engine "Trim" not available for this storage engine %s Feeds selected %s Input processes associated with these feeds - 1 year - 2 year 1 Input process associated with this feed 1 hour 1 min 10 mins 10s 12 hour 15 mins 30 mins 30s 5 mins 5s 6 hour Add the HTTP header: "Authorization: Bearer APIKEY" e.g. curl http://127.0.0.1/emoncms/feed/value.json?id=1 -H "Authorization: Bearer APIKEY" Annual Apikey authentication Append to your request URL: &apikey=APIKEY Are you sure you want to delete all the feeds data? Are you sure you want to delete? Auto CSV export Cancel Cannot use virtual feed as source Clear Clear Data Close Collapse Create new feed Daily Date time format Date time in excel format is in user timezone. Offset can be set if exporting in Unix epoch time format. Delete Delete data point Delete existent feed Delete feed Delete feed permanently Deleting a feed is permanent. Download Edit Edit feed Empty feed data up to Empty feed of all data End date & time  Error setting processlist Estimated download file size is large. Estimated download size:  Expand Export Export CSV data (timeformat=1: provides date time string format) Feed API Feed API Help Feed API helper Feed DataType:  Feed ID Feed Interval Feed Name:  Feed Start Time Feed Tag:  Feed Unit Feed name: Feed node: Feed setup actions Feeds Feeds Deleted Feeds are where your monitoring data is stored. The route for creating storage feeds is to start by creating inputs (see the inputs tab). Once you have inputs you can either log them straight to feeds or if you want you can add various levels of input processing to your inputs to create things like daily average data or to calibrate inputs before storage. Alternatively you can create Virtual feeds, this is a special feed that allows you to do post processing on existing storage feeds data, the main advantage is that it will not use additional storage space and you may modify post processing list that gets applyed on old stored data. You may want the next link as a guide for generating your request:  Get all feed fields Get feed field Get feed meta (PHPFina, PHPFiwa) Get feed process list Graph view Html If you have Input Processlist processors that use this feed, after deleting it, review that process lists or they will be in error, freezing other Inputs. Also make sure no Dashboards use the deleted feed. If you want to call any of the following actions when you're not logged in, you have the option to authenticate with the API key: Insert new data point Interval Invalid feed Invalid input Invalid proccess for Virtual Feed, try another. JSON Last updated time and value for feed Last value for multiple feeds Last value of a given feed Limit is List feeds for authenticated user List public feeds for the given user Make feed public: Monthly New Virtual Feed New virtual feed No feeds created Now Offset secs (for daily) One year ago Other Out of range Please enter a valid end date. Please enter a valid start date. Please select interval to download. Process config Read & Write: Read feed actions Read feed data actions Read only: Realtime Refresh feed size Reset feed process list Return buffer points pending write Return total engines size Returns feed data Returns histogram data Returns kwh consumed in a given power band using histogram data type Save Select all Select the time range and interval that you wish to export:  Selecting an interval shorter than the feed interval (or Auto) will use the feed interval instead. Averages are only returned for feed engines with built in averaging. Server could take a long time or abort depending on stored data size. Set feed process list Set to the current date/time Set to the start date Start Start date & time Start date must be further back in time than end date. Tag The feed list view This is a Virtual Feed, after deleting it, make sure no Dashboard continue to use the deleted feed. This is a new feature. Consider backing up your data before you continue. OK to continue? This page To use the json api the request url needs to include .json Total size of used space for feeds: Trim Trim Data Try exporting anyway? Two years ago Unable to rename multiple feeds Unselect all Update data point Update feed field Use POST parameter: "apikey=APIKEY" Virtual feed process actions Weekly Write feed data actions Project-Id-Version: emoncms3
Report-Msgid-Bugs-To: 
PO-Revision-Date: 2020-08-28 10:56+0200
Last-Translator: Aymeric THIBAUT
Language-Team: Baptiste Gaultier (Télécom Bretagne) <baptiste.gaultier@telecom-bretagne.eu>
Language: fr_FR
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Poedit-KeywordsList: _;gettext;gettext_noop
X-Poedit-Basepath: .
X-Poedit-SourceCharset: utf-8
X-Generator: Poedit 2.4.1
X-Poedit-SearchPath-0: ../../..
 "Clear" non disponible pour ce moteur de stockage "Trim" non disponible pour ce moteur de stockage %s Flux sélectionnés %s traitements Source associé à ces flux - 1 année - 2 années 1 traitement Source associé à ce flux 1 heure 1 min 10 mins 10s 12 heures 15 mins 30 mins 30s 5 mins 5s 6 heures Ajoutez l'en-tête HTTP : <b>"Authorization: Bearer APIKEY"</b> par exemple curl http://127.0.0.1/emoncms/feed/value.json?id=1 -H "Authorization: Bearer APIKEY" Annuel Authentification clé API Ajoutez à l'URL de votre requête : <b>&apikey=APIKEY</b> Êtes-vous sûr de vouloir supprimer toutes les données de ces flux ? Êtes-vous sûr de vouloir supprimer? Auto Export CSV Annuler Ne peut pas utiliser le Flux Virtuel comme source Nettoyer Nettoyer les données Fermer Replier Créer un nouveau flux Quotidien Format de l'heure de la date L'heure de la date au format excel est dans le fuseau horaire de l'utilisateur. Le décalage peut être réglé si vous exportez au format d'heure epoch Unix. Supprimer Supprimer un point de données Supprimer un flux existant Supprimer le flux Supprimer le flux de manière permanente? ATTENTION ! La suppression d'un flux est irréversible. Télécharger Modifier Modifier le flux Vider les flux de données jusqu'à Nettoyer les flux de toutes les données Date & heure de fin  Erreur définition liste de traitement La taille estimée du fichier de téléchargement est importante. Taille de téléchargement estimée :  Étendre Exporter Exporter des données CSV (timeformat=1: fournit la date et l'heure au format chaine de caractères) API Flux Aide de l'API Flux Aide de l'API Flux Type de données de flux :  Identifiant Flux Intervalle Flux Nom de flux :  Temps de départ Flux Étiquette flux :  Unité de flux Nom de flux : Nœud de flux :  Actions de paramétrage de flux Flux Flux supprimés Les flux sont l'endroit où vos données sont stockées. L'itinéraire pour créer des flux de stockage consiste à créer des sources (voir l'onglet des sources). Une fois que vous avez des sources, vous pouvez les enregistrer directement dans des flux ou, si vous le souhaitez, vous pouvez ajouter différents niveaux de traitement d'entrée à vos sources pour créer des choses comme des données moyennes quotidiennes ou pour calibrer les sources avant le stockage. Alternativement, vous pouvez créer des flux virtuels, il s'agit d'un flux spécial qui vous permet de faire un post-traitement sur les données existantes de stockage, l'avantage principal est qu'il n'utilise pas d'espace de stockage supplémentaire et que vous pouvez modifier la liste de post-traitement qui est appliquée sur les anciennes données stockées. Vous pouvez considérer le lien suivant comme un guide pour générer votre demande :  Obtenir tous les champs du flux Obtenir le champ du flux Obtenir les meta du flux (PHPFina, PHPFiwa) Obtenir la liste des traitements de flux Vue graphique Html Si vous avez des traitements qui utilisent ce flux, après l'avoir supprimé, examinez ces listes de traitements sinon ils seront en erreur, en bloquant d'autres sources. Assurez-vous également qu'aucun tableau de bord n'utilise le flux supprimé. Si vous voulez appeler une des actions suivantes sans être connecté, vous avez les options suivantes pour vous authentifier avec la clé API : Insérer un nouveau point de données Intervalle Flux non valide Source non valide Traitement non valide pour ce Flux Virtuel, essayez en un autre. JSON Dernière valeur et temps de mise à jour pour le flux Dernière valeur pour plusieurs flux Dernière valeur pour un flux donné La limite est Lister les flux de l'utilisateur authentifié Lister les flux publics pour un utilisateur donné Rendre ce flux public Mensuel Nouveau Flux Virtuel Nouveau flux virtuel Aucun flux disponible Maintenant Secondes décalage (pour quotidien) Une année précédente Autre Hors plage Entrez SVP une date de fin valide. Entrez SVP une date de début valide. Sélectionnez SVP un intervalle de téléchargement. Configuration du traitement Lecture & Écriture : Actions de flux en lecture Actions de données de flux en lecture Lecture uniquement : Temps réel Rafraîchir la taille du flux Réinitialiser la liste des traitements de flux Retourner les points de tampon en attente d'écriture Retourner la taille totale des moteurs Retourner les données du flux Retourner les données de l'histogramme Retourner les kwh consommés pour une bande de puissance donnée en utilisant un type de données histogramme Sauvegarder Tout sélectionner Sélectionner la plage et l'intervalle de temps que vous souhaitez exporter :  La sélection d'un intervalle plus petit que l'intervalle du flux (ou Auto) utilisera l'intervalle du flux à la place. Les moyennes sont retournées seulement pour les moteurs de flux avec intégration interne des moyennes. Le serveur peut prendre du temps ou abandonner suivant la taille des données enregistrées. Définir la liste des traitements de flux Définir sur la date/heure courante Définir à la date de départ Début Date & heure de début La date de début doit être antérieure à la date de fin. Étiquette Liste des flux C'est un Flux Virtuel, après avoir supprimé ce dernier, assurez-vous qu'aucun Tableau de bord continue à utiliser le champ supprimé. Ceci est une nouvelle fonctionnalité. Veuillez effectuer une sauvegarde de vos données avant de continuer. Ok pour continuer? Cette page (documentation API) Pour utiliser l'api json, vous devez ajouter .json à la fin de l'url Taille totale de l'espace utilisé pour les flux : Réduire Réduire les données Essayer l'exportation dans tous les cas? Deux années précédentes Impossible de renommer plusieurs champs Tout désélectionner Mettre à jour un point de données Mettre à jour un champ de flux Utilisez le paramètre POST : <b>"apikey=APIKEY"</b> Actions de traitements des flux virtuels Hebdomadaire Actions de données de flux en écriture 