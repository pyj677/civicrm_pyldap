civicrm_pyldap
==============

Allows you to search your civicrm install directly from your mail client. (tested with Thunderbird and Outlook)

Background
----------

I needed the functionality of https://github.com/TechToThePeople/ldapcivi as described in https://civicrm.org/blogs/chrischinchilla/civicrm-and-ldap%E2%80%A6-journey but could not live with the single user limitation and lack of SSL.  Since I have no Javascript skills, I tried to extend it in Python instead of Node.js - while acknowledging the great work done by Xavier and Chris.  I have leaned heavily on them.

Requirements
------------
The civicrm_pyldap server and CiviCRM server do not need to be in the same place.  The only extra python library needed is ldaptor.  (On Debian based systems you can apt-get install python-ldaptor.)

You might also need to read up on LDAP, here's a good start - http://php.net/manual/en/intro.ldap.php.


Install
-------
$git clone https://github.com/pyj677/civicrm_pyldap

$edit civi_ldapserver.conf //change the config to your requirements


Run
---
Ensure you are in the 'civicrm_pyldap' directory.

python civicrm_pyldap.py -f civicrm_pyldap.conf


On the CiviCRM side
-------------------
You may want to install the 'eu.tttp.qlookup' extension to provide a better contact lookup and thus the api function contact.getttpquick. However, the default CiviCRM contact search can be used instead, see the config file.

query: civicrm/contact/getttpquick

Common setup
------------
The civicrm_pyldap server needs to have the key from the civicrm_settings.php file.  It uses the password from the mail client for the api_key.  The user name can be anything, but it seems good practice to use the real user names and set up an api_key for each user - perhaps using the CiviCRM api key extension.

Use from Thunderbird
--------------------
The config file section name (delivered as [dc=example,dc=com]) must match the Base DN in Thunderbird Directory Server Properties.  Set up the same host, port as you have in the [ldap] section of your config file.  Bind DN equates to user name.  Check / uncheck SSL as apropriate for your config.  Enter the relevant api_key when prompted for a password.

Mozilla Thunderbird is a good starting point for testing, however to make it most useful, turn on LDAP debugging so you can see what was going on. You do this by following the instructions here (http://wiki.dovecot.org/Debugging/Thunderbird), but change NSPR_LOG_MODULES=IMAP:5 to NSPR_LOG_MODULES=LDAP:5.


Use from Outlook
----------------
Same as thunderbird, but the login has to be 
cn=nicolas, dc=example, dc=org (or whatever your bind DN)
