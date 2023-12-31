**-FR-**

**MfaPasslessPizazz** est conçu pour simplifier et sécuriser le déploiement et la configuration de votre environnement MFA et/ou Passwordless.

L'outil se veut être un facilitateur, réduisant la complexité inhérente à l'implémentation de ces méthodes d'authentification tout en renforçant leur sécurité.

Dans cette optique, MfaPasslessPizazz se concentre sur trois méthodes d'authentification clés, toutes reconnues pour leur accessibilité, leur fiabilité et leur robustesse en termes de sécurité :

1.  **Microsoft Authenticator (en mode mdp + Push)** : Cette application mobile de Microsoft offre un moyen rapide, pratique et sécurisé de vérifier son identité lors de la connexion à un compte ou à une application. La double authentification par mot de passe et notification push assure une sécurité renforcée. L'utilisateur reçoit une notification sur son appareil mobile et n'a qu'à approuver la demande d'authentification. Cela offre un niveau de sécurité élevé, tout en rendant l'authentification rapide et facile pour l'utilisateur.
2.  **TAP (Droit d’accès temporaire)** : Les TAP offrent un moyen efficace et flexible de donner un accès temporaire à un utilisateur, ce qui est particulièrement utile lors de la configuration initiale d'un compte ou si l'utilisateur a temporairement perdu l'accès à ses méthodes d'authentification habituelles. Le TAP est conçu pour être utilisé une seule fois et expire après une durée définie, ce qui le rend très sûr.
3.  **Clé de sécurité FIDO2** : FIDO2 est une norme d'authentification qui vise à éliminer l'utilisation de mots de passe, augmentant ainsi la sécurité. Les clés de sécurité FIDO2 offrent une méthode d'authentification à deux facteurs hautement sécurisée qui est également résistante au phishing. En plus de cela, elles sont faciles à utiliser et portables, ce qui signifie que les utilisateurs peuvent les emporter partout où ils vont.

Cette sélection permet une authentification multi-facteur flexible, sécurisée et conviviale, ainsi qu'une transition vers une authentification sans mot de passe (Passwordless), respectant à la fois les besoins de l'utilisateur et les exigences de l'industrie en matière de sécurité.

# **MfaPasslessPizazz propose 4 outils :**

## **Update Tool :**

Le centre névralgique d'MfaPasslessPizazz.

Update Tool gère les utilisateurs d'une organisation Microsoft, en les triant en fonction de leur configuration d'authentification. Il utilise des contrôles conditionnels pour dispatcher les utilisateurs dans trois groupes distincts : MFA_NotConfigured, MFA_Authenticator+FIDO2 et MFA_FIDO2_Passwordless. Cette distinction permet une gestion efficace de l'authentification multi-facteur (MFA) et de la configuration "Passwordless" (sans mot de passe).

L’outil permet ainsi une gestion complète pour différentes stratégies d'authentification au sein d'un environnement Microsoft (multi-facteur, sans mot de passe ou le combo multi-facteur+ sans mot de passe)

## **Reset Tool :**

C’est un élément essentiel de MfaPasslessPizazz qui facilite une remise à zéro des configurations d'authentification des utilisateurs au sein d'un environnement Microsoft. L'outil scrute et supprime les méthodes d'authentification assignées à chaque utilisateur spécifié, permettant ainsi une réinitialisation totale de l'authentification, incluant l'authentification par email, FIDO2, Microsoft Authenticator, téléphone, Software Oath et TAP. Suite à la réinitialisation, Reset Tool révoque tous les jetons d'authentification actifs, ce qui impose à l'utilisateur de se reconnecter à toutes ses applications.

## **Passwordless Tool :**

Le Passwordless Tool est un composant de MfaPasslessPizazz qui permet de passer un utilisateur en mode d'authentification sans mot de passe, sous condition que celui-ci ait déjà configuré une clé FIDO2. L'outil retire toutes les autres méthodes d'authentification de l'utilisateur et révoque tous les tokens actifs. Cela oblige une reconnexion via le moyen sans mot de passe uniquement, assurant ainsi une transition sécurisée vers une authentification sans mot de passe.

## **TAP Management :**

L'outil TAP Management (Temporary Access Pass) de MfaPasslessPizazz est un système d'authentification temporaire qui génère des mots de passe à usage unique pour les utilisateurs. Ces mots de passe temporaires peuvent être utilisés lorsque les utilisateurs n'ont pas accès à leur méthode d'authentification habituelle ou lors de la configuration initiale pour les utilisateurs membres de MFA_NotConfigured.

Cet outil offre la possibilité de choisir la durée de validité du mot de passe temporaire, qui peut varier de 10 minutes à 30 jours. Le TAP est généré pour un ou plusieurs utilisateurs spécifiés et les détails sont exportés exclusivement dans un fichier CSV local pour référence.

L'outil permet également de supprimer les TAP existants pour un ou plusieurs utilisateurs. Ceci est utile pour révoquer les accès temporaires s’ils ne sont plus nécessaires.

# **Comportement et interaction utilisateur en fonction des groupes de sécurité :**

## **Groupe MFA_NotConfigured**

Un utilisateur sera automatiquement affecté au groupe MFA_NotConfigured dans les cas suivants :

-   L'utilisateur n'a configuré aucune méthode d'authentification.
-   L'utilisateur a été traité par l'outil Reset Tool, qui réinitialise les configurations d'authentification.

Si un utilisateur se trouve dans le groupe MFA_NotConfigured sans TAP, lors de sa prochaine connexion, une fenêtre d'information s'affiche avec le message suivant : "Plus d'informations requises : votre organisation a besoin de plus d'informations pour préserver la sécurité du compte". L'utilisateur est alors invité à suivre les étapes suivantes :

-   Installer Microsoft Authenticator sur son smartphone.
-   Ajouter un compte professionnel à l'aide du QR code qui apparaît à l'écran.
-   Valider son inscription et son appareil en acceptant la connexion test.

Dans le cas où l'utilisateur n'aurait pas de smartphone ou si vous souhaitez lui proposer directement une solution Passwordless, vous pouvez générer un TAP à l'utilisateur et lui fournir une clé FIDO2.

Lors de sa prochaine connexion, l'utilisateur sera alors invité à "Entrer le droit d’accès temporaire".

Une fois connecté, l'utilisateur devra ajouter sa clé FIDO2 et/ou Microsoft Authenticator pour compléter son processus d'authentification et ainsi profité d’une solution hybride avec le combo MFA/Passwordless.

Cette approche permet de fournir aux utilisateurs différentes options pour sécuriser leur compte et d'adapter les méthodes d'authentification en fonction de leurs besoins et de leurs équipements *(Procdure_MFA_PASSWORLDESS incluse avec l’outil)*.

## **Groupe MFA_Authenticator+FIDO2**

Si un utilisateur qui était précédemment dans le groupe MFA_NotConfigured a configuré son Microsoft Authenticator ou le combo FIDO2+Microsoft Authenticator, il est automatiquement transféré dans le groupe MFA_Authenticator+FIDO2.

Dans ce groupe, la sécurité est légèrement allégée pour assurer une meilleure expérience utilisateur.

Lorsque l'utilisateur se trouve dans le groupe MFA_Authenticator+FIDO2, il est autorisé à contourner les méthodes d'authentification supplémentaires s'il tente de se connecter depuis des emplacements définis comme "de confiance".

Ces emplacements de confiance sont déterminés par une liste d'adresses IP publiques spécifiées dans les [Emplacements nommés](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations).

Cette approche permet à l'utilisateur de bénéficier d'une expérience plus fluide et d'un accès plus rapide aux services et applications, tout en maintenant un niveau de sécurité adéquat.

## **Groupe MFA_FIDO2_Passwordless**

L'utilisateur peut se retrouver dans le groupe MFA_FIDO2_Passwordless dans deux cas de figure :

-   Si l'utilisateur est initialement dans le groupe MFA_NotConfigured, qu'un TAP lui a été généré et qu’il n’a ajouté que sa clé FIDO2.
-   Si l'utilisateur est initialement dans le groupe MFA_Authenticator+FIDO2 et qu'il passe par l'outil "Passwordless Tool", qui supprime toutes les méthodes d'authentification de l'utilisateur sauf FIDO2.

Dans le groupe MFA_FIDO2_Passwordless, l'utilisateur bénéficie d'une expérience d'authentification sans mot de passe, où seule sa clé de sécurité FIDO2 est requise pour accéder aux services et applications.

Cela simplifie grandement le processus d'authentification tout en maintenant un niveau élevé de sécurité.

Toutefois, il est important de noter que toutes les applications utilisées par l'utilisateur doivent prendre en charge l'authentification sans mot de passe (Passwordless).

Certaines applications spécifiques, telles que certains client VPN utilisant la connexion Radius, peuvent ne pas être compatible Passwordless et nécessiter une méthode d'authentification supplémentaire, telle qu'une notification push.

Il est donc recommandé de vérifier la compatibilité des applications avec l'authentification sans mot de passe avant de basculer vers le groupe MFA_FIDO2_Passwordless.

Cela afin de garantir une expérience d'authentification fluide et sécurisée pour l'utilisateur, en tenant compte des exigences spécifiques de chaque application.

# **Paramétrage et Prérequis**

MfaPasslessPizazz est développé autour de PowerShell, Microsoft Azure et Microsoft Graph.

C'est en combinant [Paramètre des Méthodes d’authentification](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AuthMethodsSettings), [Stratégies de Méthodes d'authentification](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods), [Points forts d’authentification](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AuthStrengths), [Détails de l’inscription de l’utilisateur](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails), [Stratégies d’Accès conditionnel](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/PoliciesList), [Emplacements nommés](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations) et [Groupes de Sécurité](https://portal.azure.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups) que MfaPasslessPizazz conditionne les actions de ses Scripts.

À ce titre, certaines configurations préalables sont requises.

Pour cela, MfaPasslessPizazz dispose d’un module d’**AutoConf** qui préparera votre environnement en 1 clic ! (La seule et unique interaction attendue sera, si vous le souhaitez, la saisie de votre liste d’@IP Safe).

Enfin, sachez qu’avant de pouvoir exécuter les outils d’MfaPasslessPizazz, En guise de mesure préemptive, il vous faudra **obligatoirement** renseigner une liste d’utilisateur à exclure des différents traitements.

# **Le Mot de la Fin**

MfaPasslessPizazz a été conçu pour simplifier et sécuriser les déploiements d'authentification MFA et Passwordless dans les environnements Azure AD. En réponse à la confusion fréquente entre MFA et Passwordless, ainsi qu'au manque de maîtrise de l'environnement Azure AD qui peut décourager certaines organisations, j'ai voulu rendre l'adoption de ces méthodes d'authentification robustes plus accessible.

L'objectif principal de MfaPasslessPizazz est de faciliter et de renforcer la sécurité des déploiements d'authentification. Pour cela, j'ai pris en compte les défis spécifiques auxquels les administrateurs sont confrontés en fournissant une solution allant de l'autoconfiguration aux procédures d'inscription simplifiées prêtes à être partagées avec les utilisateurs finaux. Vous disposez ainsi d'un ensemble complet d'outils qui simplifient non seulement la configuration technique, mais aussi l'expérience des utilisateurs finaux lors de leur inscription.

De plus, je souhaite que cet outil donne la confiance nécessaire à d'autres administrateurs pour se lancer dans l'aventure de l'authentification Azure AD et de l'API Graph. J'ai pris le temps d'écrire un script propre, aéré et documenté pour aider les administrateurs aventuriers à personnaliser l'outil en fonction de leurs besoins spécifiques.

Amis administrateurs, n'hésitez pas à explorer les possibilités infinies offertes par l'authentification Azure AD et l'API Graph. Avec MfaPasslessPizazz entre vos mains, vous disposez d'un outil puissant pour déployer des méthodes d'authentification robustes et sécurisées dans votre environnement Azure AD.

Je vous souhaite un bon déploiement et que votre aventure d'authentification soit couronnée de succès !

**-EN-**

**MfaPasslessPizazz** Is designed to simplify and secure the deployment and configuration of your MFA and/or Passwordless environment.

The tool aims to be a facilitator, reducing the complexity inherent in implementing these authentication methods while enhancing their security.

With this goal in mind, MfaPasslessPizazz focuses on three key authentication methods, all recognized for their accessibility, reliability, and robust security:

1.  **Microsoft Authenticator (Password + Push mode):** This Microsoft mobile application offers a fast, convenient, and secure way to verify identity when logging into an account or application. The combination of password and push notification for two-factor authentication ensures enhanced security. The user receives a notification on their mobile device and simply needs to approve the authentication request. This provides a high level of security while making authentication quick and easy for the user.
2.  **TAP (Temporary Access Pass):** TAP provides an efficient and flexible way to grant temporary access to a user, which is particularly useful during initial account setup or if the user temporarily loses access to their usual authentication methods. TAP is designed for one-time use and expires after a defined period, making it very secure.
3.  **FIDO2 Security Key:** FIDO2 is an authentication standard that aims to eliminate the use of passwords, thereby increasing security. FIDO2 security keys provide a highly secure two-factor authentication method that is also resistant to phishing. Additionally, they are easy to use and portable, allowing users to carry them wherever they go.

This selection enables flexible, secure, and user-friendly multi-factor authentication as well as a transition to Passwordless authentication, meeting both user needs and industry security requirements.

# **MfaPasslessPizazz offers 4 Tools:**

## **Update Tool:**

The central component of MfaPasslessPizazz.

The Update Tool manages users within a Microsoft organization, sorting them based on their authentication configuration. It uses conditional controls to allocate users into three distinct groups: MFA_NotConfigured, MFA_Authenticator+FIDO2, and MFA_FIDO2_Passwordless. This distinction allows for efficient management of multi-factor authentication (MFA) and Passwordless configuration. The tool provides comprehensive management for different authentication strategies within a Microsoft environment (multi-factor, Passwordless, or the combination of both).

## **Reset Tool:**

An essential part of MfaPasslessPizazz that facilitates the reset of user authentication configurations within a Microsoft environment. The tool scans and removes assigned authentication methods for each specified user, enabling a complete reset of authentication, including email authentication, FIDO2, Microsoft Authenticator, phone, Software Oath, and TAP. After the reset, the Reset Tool revokes all active authentication tokens, requiring the user to reconnect to all their applications.

## **Passwordless Tool:**

The Passwordless Tool is a component of MfaPasslessPizazz that allows a user to transition to Passwordless authentication mode, provided they have already configured a FIDO2 key. The tool removes all other authentication methods for the user and revokes all active tokens. This enforces reconnection using the Passwordless method only, ensuring a secure transition to Passwordless authentication.

## **TAP Management:**

The TAP (Temporary Access Pass) Management tool in MfaPasslessPizazz is a temporary authentication system that generates one-time-use passwords for users. These temporary passwords can be used when users don't have access to their usual authentication method or during initial configuration for MFA_NotConfigured users. This tool allows you to choose the validity duration of the temporary password, ranging from 10 minutes to 30 days. The TAP is generated for one or more specified users, and the details are exported exclusively to a local CSV file for reference. The tool also provides the ability to remove existing TAPs for one or more users, which is useful for revoking temporary access if no longer needed.

# **User Behavior and Interaction based on Security Groups:**

## **MFA_NotConfigured Group:**

Users are automatically assigned to the MFA_NotConfigured group in the following cases:

-   The user has not configured any authentication method.
-   The user has been processed by the Reset Tool, which resets authentication configurations.

If a user is in the MFA_NotConfigured group without TAP, upon their next login, an information window will appear with the following message: "More information required: Your organization requires additional information to maintain account security."

The user Is then prompted to follow these steps:

-   Install Microsoft Authenticator on their smartphone.
-   Add a work account using the QR code displayed on the screen.
-   Validate their registration and device by accepting the test login.

In the case where the user does not have a smartphone or if you want to directly offer them a Passwordless solution, you can generate a TAP for the user and provide a FIDO2 key.

On their next login, the user will be prompted to "Enter the temporary access right."

Once connected, the user needs to add their FIDO2 key and/or Microsoft Authenticator to complete the authentication process and enjoy a hybrid MFA/Passwordless solution.

This approach provides users with different options to secure their accounts and adapts authentication methods based on their needs and equipment *(MFA_PASSWORDLESS procedure included with the tool)*.

## **MFA_Authenticator+FIDO2 Group:**

If a user who was previously in the MFA_NotConfigured group configures their Microsoft Authenticator or the FIDO2+Microsoft Authenticator combination, they are automatically moved to the MFA_Authenticator+FIDO2 group.

In this group, security is slightly relaxed to ensure a better user experience.

When a user is in the MFA_Authenticator+FIDO2 group, they are allowed to bypass additional authentication methods when attempting to log in from defined "trusted" locations.

These trusted locations are determined by a list of specified public IP addresses in [Named Locations](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations).

This approach allows users to benefit from a smoother experience and quicker access to services and applications while maintaining an adequate level of security.

## **MFA_FIDO2_Passwordless Group:**

Users can be in the MFA_FIDO2_Passwordless group in two scenarios:

-   If the user is initially in the MFA_NotConfigured group, a TAP is generated for them, and they have only added their FIDO2 key.
-   If the user is initially in the MFA_Authenticator+FIDO2 group and goes through the "Passwordless Tool," which removes all authentication methods except FIDO2.

In the MFA_FIDO2_Passwordless group, the user enjoys a Passwordless authentication experience, where only their FIDO2 security key is required to access services and applications.

This greatly simplifies the authentication process while maintaining a high level of security.

However, it is important to note that all applications used by the user must support Passwordless authentication.

Some specific applications, such as certain VPN clients using Radius connection, may not be compatible with Passwordless authentication and may require an additional authentication method, such as a push notification.

Therefore, it is recommended to check the compatibility of applications with Passwordless authentication before transitioning to the MFA_FIDO2_Passwordless group.

This ensures a smooth and secure authentication experience for the user, considering the specific requirements of each application.

# **Configuration and Prerequisites:**

MfaPasslessPizazz is developed around PowerShell, Microsoft Azure, and Microsoft Graph.

By combining [Authentication Methods Settings](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AuthMethodsSettings), [Authentication Methods Policy](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods), [Authentication Strengths](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AuthStrengths), [User Registration Details](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails), [Conditional Access Policies](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/PoliciesList), [Named Locations](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations), and [Security Groups](https://portal.azure.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups), MfaPasslessPizazz conditions the actions of its scripts.

As such, certain pre-configurations are required.

For this purpose, MfaPasslessPizazz provides an **AutoConf** module that prepares your environment with just one click! (The only interaction expected is, if desired, entering your list of Safe IP addresses).

Finally, before executing the MfaPasslessPizazz tools, as a preemptive measure, you **must provide** a list of users to be excluded from the various processes.

# **Closing Remarks:**

MfaPasslessPizazz was designed to simplify and secure MFA and Passwordless authentication deployments in Azure AD environments. In response to the frequent confusion between MFA and Passwordless, as well as the lack of familiarity with the Azure AD environment that can discourage some organizations, I wanted to make the adoption of robust authentication methods more accessible.

The primary goal of MfaPasslessPizazz is to facilitate and enhance the security of authentication deployments. To achieve this, I have considered the specific challenges administrators face by providing a solution that ranges from self-configuration to simplified enrollment procedures ready to be shared with end users. You now have a comprehensive set of tools that not only simplify the technical configuration but also improve the end-user experience during their enrollment.

Furthermore, I hope that this tool instills the confidence in other administrators to embark on the Azure AD authentication and Graph API adventure. I have taken the time to write clean, organized, and documented scripts to assist adventurous administrators in customizing the tool according to their specific needs.

Administrators, feel free to explore the infinite possibilities offered by Azure AD authentication and the Graph API. With MfaPasslessPizazz in your hands, you have a powerful tool to deploy robust and secure authentication methods in your Azure AD environment.

Wishing you successful deployments and a rewarding authentication Journey!
