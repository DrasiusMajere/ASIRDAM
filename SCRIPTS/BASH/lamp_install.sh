#!/bin/bash

#
# AUTHOR: DIEGO SANCHEZ SANCHEZ [ DRASIUS ]
# LICENSE CC BY-NC-SA
#
# FOR LAMPP INSTALLATION
# you can choose between Mysql and Mariadb
# intalled the last stable versions
#
# *** if you experience any kind of system instability system ***
# *** I recommend you to do a CLEAN INSTALL ***
#

###           ###
### FUNCTIONS ###
###           ###

# CHECK IF A LIBRARY EXISTS
# 
# PARAMETERS
#   $1 => package name
#
# RETURNS
#   true or false
#
exist() {
  if [[ -d "/var/lib/$1" || -e "/bin/$1" ]]; then
    printf true
  else
    printf false
  fi
}


# GENERATE RANDOMS STRINGS AS SECRETS
# please notice this is not using a PBKDF
# Use bcrypt, crypt, lyra2, argon2 to store passwords
# 
# PARAMETERS
#   $1 => final length of the base64, displayed characters
#   $2 => size in bytes [32 bytes - 64 hex]
#
# RETURNS
#   $secret => a base64 encoded string
#
generateSecret() {
  while true; do
    secret="$(openssl rand -base64 ${2:-32} | cut -c 1-${1:-32})"
    if [[ ! "$secret" =~ "/" ]]; then
      break
    fi
  done
  printf "$secret"
}

# SET PHPMYADMIN PASSWORD - PMA USER
#   Create or set password for pma user
#   Either You can set this password by providing a customized one
#   or you can set it randomly 
# 
# PARAMETERS
#  $1 => minimum length [8]
#   $2 => type of strength (0-15) [1]
#     1 -> only check the length
#     2 -> upper and lower letters mixed
#     4 -> numbers included
#     8 -> special characters included 
#
setPmaPassword() {
  printf "\nA phpmyadmin user will be created or overwritten."
  printf "\nIf you dont want a custom password, it will be randomly generated" 
  printf "\nDo you want to set a custom password? [(y)es | (n)o | (q)uit ] (n): "
  option=$(normalizeInput n) 
  if [[ " y yes " =~ " $option " ]]; then  
    validatePassword 8 15
    pmaPassword=$password 
  elif [[ " q quit " =~ " $option " ]]; then
    exit 0;
  else
    pmaPassword=$(generateSecret 16)
  fi
}

# REMOVE LEADING AND TRAILING SPACES
#
#
# PARAMETERS
#   $1 => value in which spaces are removed
#
# RETURNS
#   $val => value without spaces
#
trim() {
  local val=$1

  val="${val##+( )}"
  val="${val%%+( )}"

  printf "$val"
}

# NORMALIZE STRINGS
# Read a value and normalize it
#   It is used to compare 2 strings fairly
#   It is not case sensitive - lowercase
#   Remove leading and trailing spaces - trim
# 
# PARAMETERS
#   $1 => value to normalize
#   $@ => arguments space separated that reprsents flags to stdin
#
# RETURNS
#   $val => normalized value
#
normalizeInput() {
  local val=""
  local len=$(expr ${#@} - 1)

  read ${@:2:len} -r val
  if [[ -z "$val" && -n "$1" ]]; then 
    val="$1"
  fi
  val="${val,,}"

  printf "$(trim $val)"
}

# ASK FOR A PASSWORD
##
# PARAMETERS
#   $1 => minimum length [8]
#   $2 => type of strength (0-15) [1]
#     1 -> only check the length
#     2 -> upper and lower letters mixed
#     4 -> numbers included
#     8 -> special characters included
#
# RETURNS
#   $password => string that meets the passed criteria
#
askPassword() {  
  local val=false
  local password=""

  while ! $val; do
    local lenPass=${1:-8}
    local strength=${2:-1}
    password=""
    val=true

    read -r -s password
   
    if [[ $((strength - 8)) -ge 0 ]]; then
      strength=$((strength - 8))    
      if [[ ! "$password" =~ [^A-Za-z0-9] ]]; then
        val=false
      fi
    fi
    if [[ $((strength - 4)) -ge 0 ]]; then
      strength=$((strength - 4))
      if [[ ! "$password" =~ [0-9] ]]; then
        val=false
      fi
    fi
    if [[ $((strength - 2)) -ge 0 ]]; then
      strength=$((strength - 2))
      if [[ ! "$password" =~ ([a-z][A-Z]|[A-Z][a-z]) ]]; then
        val=false
      fi
    fi
    if [[ $((strength - 1)) -ge 0 ]]; then
      strength=$((strength - 1))
      if [[ ${#password} -lt $lenPass ]]; then
        val=false
      fi
    fi

  done 

  printf "$password"
}

# VALIDATE 2 PASSWORD
#   check if 2 passwords meet the requirements
#   and their values are equal
#
# PARAMETERS
#   $1 => minimum length [8]
#   $2 => type of strength (0-15) [1]
#     1 -> only check the length
#     2 -> upper and lower letters mixed
#     4 -> numbers included
#     8 -> special characters included
#
# GLOBAL
#   $password => string that meets the passed criteria
#
validatePassword() {  
  while true; do
    local lenPass=${1:-8}
    local strength=${2:-1}
    
    printf "\nPassword must meet these requirements"
    if [[ $((strength - 8)) -ge 0 ]]; then
      strength=$((strength - 8))    
      printf "\n\tSpecial"
    fi
    if [[ $((strength - 4)) -ge 0 ]]; then
      strength=$((strength - 4))
      printf "\n\tNumbers"
    fi
    if [[ $((strength - 2)) -ge 0 ]]; then
      strength=$((strength - 2))
      printf "\n\tUpperscase and lowercase"
    fi
    if [[ $((strength - 1)) -ge 0 ]]; then
      strength=$((strength - 1))
      printf "\n\tMin. $lenPass"
    fi

    printf "\nSet the password: "

    password="$(askPassword $lenPass $2)"
    printf "$password\n" | sed -r 's/./*/g'

    printf "\nRepeat the root password: " 
    password2=$(askPassword $lenPass $2)    
    printf "$password2\n" | sed -r 's/./*/g'

    if [[ "$password" == "$password2" ]]; then
      break
    else
      printf "***Passwords do not match***\n"
    fi
  done
}

# GET THE FORMER DATABASE
#   when databases are distinct you need backup the database files
#   and config files, and the server daemon as well
# 
#
# RETURNS
#   $oldDB => the name of the database: mysql | mariadb
#
getOldDB() {
  local oldDB=""
  local isMaria="$(mysql --version 2>/dev/null | grep "MariaDB" 2>/dev/null)"
  if ! $(exist mysql); then
    oldDB=""
  elif [[ -n "$isMaria" ]]; then
    oldDB="mariadb"
  else
    oldDB="mysql"
  fi 

  printf "$oldDB"
}

# ask for a Full clean install
# it detects if database and config files are present in the system
# if databases are different to avoid issues of incompatibilities
# certain folders will be backup and deleted
# and older database services should be removed or disable to avoid conflicts
#
# PARAMETERS
#   $1 => service name to be deleted
#
doDatabaseCleaning() {
  local folder="$1"
  # mariadb is based on mysql and it works against mysql folders and libs
  if [[ " mariadb maria " =~ " $1 " ]]; then
    folder="mysql"
  fi
  if [[ -e "/var/lib/$folder" || -e "/etc/$folder" ]]; then    
    if [[ -n "$1" &&  " mysql mariadb maria " =~ " $1 "  ]]; then 
      if [[ -n "$oldDatabase" && "$oldDatabase" != "$1" ]]; then
        printf "Former Database was: $oldDatabase\n" 
        printf "New Database is: $1\n" 
        sudo systemctl disable --now "$oldDatabase" > /dev/null 2>&1
        sudo rm -r "/var/lib/${folder}-8"* > /dev/null 2>&1
        sudo rm -r "/var/lib/bak${folder}" 2>/dev/null
        sudo mv -f "/var/lib/${folder}" "/var/lib/bakmysql" 2>/dev/null        
        sudo apt-get remove -y "${oldDatabase}"-{server,client} > /dev/null 2>&1
      fi
    fi
  fi
}

# do a Full clean install
#   database folders and config files will be backup and deleted
#   all related packages from that services should be purged
#
# PARAMETERS
#   $1 => service name to be deleted
#
doFullCleaning() {
  local folder="$1"
  # mariadb is based on mysql and it works against mysql folders and libs
  if [[ " database mariadb maria mysql " =~ " $1 " ]]; then
    folder="mysql"
  fi   
  printf "Creating backup of ${folder:-$1}\n"
  # just in case the service is using these files and block them
  sudo systemctl disable --now "$1" > /dev/null 2>&1

  sudo rm -r "/var/lib/bak${folder}" 2>/dev/null
  sudo mv "/var/lib/${folder}" "/var/lib/bak${folder}" 2>/dev/null
  sudo rm -r "/etc/bak${folder}" 2>/dev/null
  sudo mv "/etc/${folder}" "/etc/bak${folder}" 2>/dev/null
  # if apache2 is removed we also must ensure php is deleted as well 
  if [[ " apache apache2 " =~ " $folder " ]]; then
    printf  "y\n" | doCleaning "php"
  fi
  printf "\neliminando: $folder\n"

  sudo apt-get purge -y "${folder}"* > /dev/null 2>&1
  
}


# ask for a Full clean install
#   it detects if libs and config files are present in the system
#   certain folders will be backup and deleted
#   all related packages from that services will be purged
#
# PARAMETERS
#   $1 => service name to be deleted
#
askForFullCleaning() {
  local folder="$1"
  # mariadb is based on mysql and it works against mysql folders and libs
  if [[ " mariadb maria " =~ " $1 " ]]; then
    folder="mysql"
  fi
  if [[ -d "/var/lib/$folder" || -d "/etc/$folder" ]]; then
    printf "\nIt has been detected a prior ${folder:-$1} install...\n";
    printf "Do you want to do a CLEAN install? [(y)es | (n)o | (q)uit] (n): ";
    local cleanInstall="$(normalizeInput n)"
   
    if [[ " y yes" =~ " $cleanInstall " ]]; then
      if [[ -n "$1" &&  " mysql mariadb maria " =~ " $1 " ]]; then
        cleanInstalls[database]=true
      else
        cleanInstalls[$1]=true
      fi
    elif [[ " q quit " =~ " $cleanInstall " ]]; then
      exit 0;
    fi
  fi
}

##      ##
## INIT ##
##      ##
printf "Please read the following questions carefully\n"

# UPDATE REPOSITORIES
printf "\nUPDATING REPOSITORIES...\n"
sudo apt-get update > /dev/null

# INSTALLING TOOLS
# htpasswd
sudo apt-get install -y apache2-utils > /dev/null

# last exit code from the above command
# if user doesn't provide a valid password exit the script
errorSudo=$?
if [[ $errorSudo -ne 0 ]]; then
  exit $errorSudo
fi

# SETTING DATABASE TYPE
oldDatabase="$(getOldDB)"

printf "\nWhat database are you going to install? [mysql | mariadb | (q)uit] (mysql): "
while true; do
  database="$(normalizeInput mysql)"
  if [[ " mysql mariadb " =~ " $database " ]]; then
    break
  elif [[ " q quit " =~ " $database " ]]; then
    exit 0
  fi
done 

# MAP or DICTIONARY to store what services require clean installs
declare -A cleanInstalls
cleanInstalls[phpmyadmin]=false
cleanInstalls[database]=false
cleanInstalls[apache2]=false
cleanInstalls[php]=false

# DO CLEANINGS
# to set cleanInstalls map
askForFullCleaning "$database"

askForFullCleaning "php"

askForFullCleaning "apache2"

# SETTING OLD DATABASE PASSWORD
# if you dont want to clean any database
# old root password is needed to access the current database 
if ! ${cleanInstalls[database]} && [[ -d "/var/lib/mysql" ]]; then  
  while true; do
    printf "\nEnter your former DATABASE 'root'@'localhost' PASSWORD [(q)uit]: "
    read -r -s oldRootPassword
    if [[ " q quit " =~ " $oldRootPassword " ]]; then
      exit 1;
    fi
    if [[ -n $oldRootPassword ]]; then
      printf "\nChecking the password, please wait.."
      # we should check if password is right and for that
      # one database service must be installed on the system
      sudo systemctl enable --now "mysql" > /dev/null 2>&1
      sudo systemctl enable --now "mariadb" > /dev/null 2>&1  
      mysql -uroot -p"$oldRootPassword" -e "quit" > /dev/null 2>&1
      if [[ $? -ne 0 ]]; then
        printf "***It is WRONG***\n"      
      else
        printf "***It is VALID***\n"
        break
      fi
    fi
  done
fi

# we give the opportunity to the user to change the current password
#  
if [[ -n "$oldRootPassword" ]]; then
  printf "\nYou already have a fomer database root password"
  printf "\nDo you want to use it? [(y)es | (n)o] (y): " 
  usePass="$(normalizeInput y)"
  if [[ " y yes " =~ " $usePass " ]]; then
    rootPassword="$oldRootPassword"
  fi
fi

# SETTING NEW DATABASE PASSWORD
# if you dont provide a former database former
# we need to set a new one
if [[ -z "$rootPassword" ]]; then
  printf "\nSet the new root password"
  validatePassword
  rootPassword=$password
fi


# PHPMYADMIN CONFIG
# if any previous version

if [[ -d "/usr/share/phpmyadmin" ]]; then
  printf "\nIt was detected a prior phpmyadmin install." 
  printf "\nDo you want to do a clean install? [(y)es | (n)o | (q)uit] (n): " 
  option="$(normalizeInput n)"
  if [[ " y yes " =~ " $option " ]]; then
    cleanInstalls[phpmyadmin]=true
  elif [[ " q quit " =~ " $option " ]]; then
      exit 0;
  fi
fi

# fresh installation either it does not exist or user want clean install
if [[ ! -d "/usr/share/phpmyadmin" ]] || ${cleanInstalls[phpmyadmin]}; then
  pmaVersion="5.2.0"
  printf "\nWhich phpmyadmin version do you want to deploy? ($pmaVersion): "
  pmaVersion="$(normalizeInput $pmaVersion)"

  setPmaPassword
else
  # Look for the pma in the current database
  existPma="$(mysql --user="root" --password="$rootPassword" -e "Select user from mysql.user where user='pma';" 2>/dev/null)"
  #
  if [[ -n "$existPma" ]]; then
    printf "\nThere is already a phpmyadmin pma user created."
    printf "\n\tDo you want to change its password? [(y)es | (n)o | (q)uit] (n): "
    option="$(normalizeInput n)"
    if [[ " y yes " =~ " $option " ]]; then    
      setPmaPassword
    # if exist a pma user and want to do a cleanisntall or differten databases
    # it is required to have the current pasword
    elif [[ "$oldDatabase" != "$database" ]] || ${cleanInstalls[database]}; then  
      while true; do
        printf "\nEnter your former DATABASE 'pma'@'localhost' PASSWORD [(q)uit]: "
        read -r -s pmaPassword
        if [[ " q quit " =~ " $pmaPassword " ]]; then
          exit 1;
        fi
        if [[ -n $pmaPassword ]]; then
          printf "\nChecking the password, please wait.."
          # we should check if password is rigth and for that
          # one database service must be installed on the system
          sudo systemctl enable --now "mysql" > /dev/null 2>&1
          sudo systemctl enable --now "mariadb" > /dev/null 2>&1  
          mysql -u"pma" -p"$pmaPassword" -e "quit" > /dev/null 2>&1
          if [[ $? -ne 0 ]]; then
            printf "***It is WRONG***\n"      
          else
            printf "***It is VALID***\n"
            break
          fi
        fi
      done
    elif [[ " q quit " =~ " $option " ]]; then
      exit 0;
    fi
  else
    setPmaPassword
  fi
fi

# SETTING HTPASSWD for accessing routes within phpmyadmin
if [[ ! -d "/etc/phpmyadmin" || ! -e "/etc/phpmyadmin/htpasswd.setup" ]]; then
  sudo mkdir -p /etc/phpmyadmin > /dev/null 2>&1
  sudo htpasswd -cBb /etc/phpmyadmin/htpasswd.setup phpmyadmin "$rootPassword" > /dev/null
fi

if [[ -f  /etc/phpmyadmin/htpasswd.setup ]]; then
  printf "\nIt has been detected a previous phpmyadmin htpasswd file."
  printf "\nDo you want to create another password (rootPassword by default) for accessing" 
  printf "\n\tto restricted areas in phpmyadmin? [(y)es | (n)o | (q)uit] (n): "
  option=$(normalizeInput n)
  if [[ " y yes " =~ " $option "  ]]; then
    printf "Enter the username (phpmyadmin): "
    htuser=$(normalizeInput phpmyadmin)
    sudo htpasswd -B /etc/phpmyadmin/htpasswd.setup "$htuser"
  elif [[ " q quit " =~ " $option " ]]; then
    exit 0;
  fi
fi


# DO CLEANINGS
# check if you are installed different databases 
doDatabaseCleaning "$database"

# do full clean installs
for key in "${!cleanInstalls[@]}"; do
  if ${cleanInstalls[$key]} && [[ "$key" != "phpmyadmin" ]]; then
    doFullCleaning "$key"
  fi
done

# INSTALLING APACHE
if ${cleanInstalls[apache2]}  || ! $(exist apache2); then
  printf "\nINSTALLING apache...\n"
  sudo apt-get install -y apache2 wget unzip > /dev/null
  sudo systemctl restart apache2 > /dev/null
fi

# INSTALLING PHP
if ${cleanInstalls[php]}  || ! $(exist php); then
  printf "\nINTALLING php AND extensions...\n"
  sudo apt-get install -y php php-{curl,zip,json,mbstring,mysql} > /dev/null
  sudo systemctl restart apache2 > /dev/null
fi

# INSTALLING DATABASES
# only if they are different databases or full clean installs
if [[ "$oldDatabase" != "$database" ]] || ! $(exist mysql) ||  ${cleanInstalls[database]}; then
  printf "\nINSTALLING $database...\n"
  sudo apt-get install -y "$database"-{server,client} > /dev/null
  sudo systemctl restart "$database" > /dev/null
fi


# CONFIGURING DATABASES
printf "\n\t=> Configuring $database...\n"
if [[ "$database" == "mariadb" ]]; then
  # CONFIGURING MARIADB
  # the first time you install or if you dont remember it
  if [[ -z "${oldRootPassword}" ]]; then
    sudo mysql -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${rootPassword}';" > /dev/null 2>&1
  else
    sudo mysql -uroot -p"${oldRootPassword}" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${rootPassword}';" > /dev/null 2>&1
  fi    
  printf "${rootPassword}\nn\nn\ny\ny\ny\ny\n" | mysql_secure_installation > /dev/null

elif [[ "$database" == "mysql" ]]; then
  # CONFIGURING MYSQL
  if [[ -z "${oldRootPassword}" ]]; then
    sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '${rootPassword}';" > /dev/null 2>&1    
  else
    # once you enable validate_password it wont be able to configured again
    # you can set this to a different level or uninstall validate_password plugin
    sudo mysql -p"${oldRootPassword}" -e "SET GLOBAL validate_password.policy=LOW;" > /dev/null 2>&1
    sudo mysql -p"${oldRootPassword}" -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '${rootPassword}';" > /dev/null 2>&1        
  fi 

  if [[ "$oldDatabase" != "$database" ]] || ${cleanInstalls[database]}; then
    printf "y\n0\nn\ny\ny\ny\ny\n" | mysql_secure_installation --user="root" --password="$rootPassword" > /dev/null 2>&1
  else
    printf "n\ny\ny\ny\ny\n" | mysql_secure_installation --user="root" --password="$rootPassword" > /dev/null 2>&1
  fi
else
  exit 1;
fi


# INSTALL PHPMYADMIN
# phpmyadmin config file
pmaConfig="config.inc.php" 

# to create phpmyadmin database and user when databases are different 
# or want a fresh install of databases or phpmyadmin

if [[ -n "$rootPassword" ]] && ([[ "$oldDatabase" != "$database" ]] || ${cleanInstalls[database]}) || ${cleanInstalls[phpmyadmin]}; then
  printf "\nINSTALLING phpmyadmin...\n"
  printf "\n\t=> Downloading files...\n"
  cd
  wget "https://files.phpmyadmin.net/phpMyAdmin/${pmaVersion}/phpMyAdmin-${pmaVersion}-all-languages.zip" > /dev/null 2>&1
  printf "\n\t=> Decompressing files...\n"
  unzip -qo phpMyAdmin-${pmaVersion}-all-languages.zip 

  printf "\n\t=> Configuring files...\n"
  sudo rm -r /usr/share/phpmyadmin 2>/dev/null
  sudo mv -f "phpMyAdmin-${pmaVersion}-all-languages" /usr/share/phpmyadmin 2>/dev/null
  sudo chown -R root:root /usr/share/phpmyadmin
  sudo install -d /usr/share/phpmyadmin/tmp  -o www-data -g www-data -m 777 2>/dev/null

   # PMA DATABASE
  printf "\n\t=> Creating phpmyadmin database in $database...\n"
  mysql --user="root" --password="$rootPassword" < /usr/share/phpmyadmin/sql/create_tables.sql  > /dev/null 2>&1
  # CREATE PHPMYADMIN PMA USER, we need root and pma password
  if [[ -n "$pmaPassword" ]]; then   
    printf "\n\t=> Creating phpmyadmin pma user...\n"
    pma="'pma'@'localhost'"
    mysql --user="root" --password="$rootPassword" -e "CREATE USER $pma IDENTIFIED BY '$pmaPassword';" > /dev/null 2>&1
    mysql --user="root" --password="$rootPassword" -e "GRANT ALL PRIVILEGES on phpmyadmin.* TO $pma;" > /dev/null 2>&1
    mysql --user="root" --password="$rootPassword" -e "FLUSH PRIVILEGES;" > /dev/null 2>&1
  fi

  # initial setup of phpmyadmin config file
  # phpmyadmin.conf file in apache
  cat > phpmyadmin.conf << EOF
  Alias /phpmyadmin /usr/share/phpmyadmin

  <Directory /usr/share/phpmyadmin>
    Options Indexes FollowSymLinks
    DirectoryIndex index.php
    <IfModule mod_php8.c>
      AddType application/x-httpd-php .php
      php_flag magic_quotes_gpc Off
      php_flag track_vars On
      php_flag register_globals Off
      php_value include_path .
    </IfModule>	
  </Directory>

  # Authorize for setup
  <Directory /usr/share/phpmyadmin/setup>
    <IfModule mod_authn_file.c>
      AuthType Basic
      AuthName "phpMyAdmin Setup"
      AuthUserFile /etc/phpmyadmin/htpasswd.setup
    </IfModule>
    Require valid-user
  </Directory>

  # Disallow web access to directories that don't need it
  <Directory /usr/share/phpmyadmin/libraries>
    Require all denied
  </Directory>

  <Directory /usr/share/phpmyadmin/setup/lib>
    Require all denied
  </Directory>
EOF

  # we enable this configuration in apache2
  sudo mv -f phpmyadmin.conf /etc/apache2/conf-available/ 2>/dev/null
  sudo a2enconf phpmyadmin.conf > /dev/null 2>&1

  # PHPMYADMIN CONFIG FILE
  # we need pma user to control the storing of phpmyadmin files
  # and access to its database
  # we need blowfish_secret because we are using autentication based on cookies
  printf "\n\t=> Patching $pmaConfig...\n"
  cat > script.sed << EOF
  s/\['blowfish_secret'\] = ''/['blowfish_secret'] = '$(generateSecret)'/
  s/\/\/ \$cfg\['Servers'\]\[\$i\]/\$cfg\['Servers'\]\[\$i\]/g
  s/\$cfg\['Servers'\]\[\$i\]\['controlhost'\] = '';/\$cfg\['Servers'\]\[\$i\]\['controlhost'\] = 'localhost';/
  \$a \$cfg\['TempDir'\] = '/usr/share/phpmyadmin/tmp';
EOF
  sudo sed -f script.sed /usr/share/phpmyadmin/config.sample.inc.php > "$pmaConfig"
  sudo cp -f "$pmaConfig" /usr/share/phpmyadmin/"$pmaConfig" 2>/dev/null
fi

# if pma password was set, that's it, you change it o create it from scratch
# you must update password in database and in the config file
if [[ -n "$pmaPassword" ]]; then
  printf "42d\n" >> script.sed
  printf "43i \$cfg\['Servers'\]\[\$i\]\['controlpass'\] = '$pmaPassword';" >> script.sed
  sudo sed -f script.sed /usr/share/phpmyadmin/"$pmaConfig" > "$pmaConfig"
  sudo cp -f "$pmaConfig" /usr/share/phpmyadmin/"$pmaConfig" 2>/dev/null

  mysql --user="root" --password="$rootPassword" -e "ALTER USER $pma IDENTIFIED BY '$pmaPassword';" > /dev/null 2>&1
  mysql --user="root" --password="$rootPassword" -e "FLUSH PRIVILEGES;" > /dev/null 2>&1
fi

# For certain changes take effect after the modifications
sudo systemctl restart apache2 > /dev/null 2>&1

# deleting unused files
printf "\nReleasing used resources...\n"
if [[ -f "script.sed" ]]; then
  rm $pmaConfig script.sed
fi
if [[ -n "$rootPassword" ]] && ([[ "$oldDatabase" != "$database" ]] || ${cleanInstalls[database]}) || ${cleanInstalls[phpmyadmin]}; then
  printf "Removing phpmyadmin files...\n"
  rm "phpMyAdmin-${pmaVersion}-all-languages"*
fi

# REMARKABLE INFO
printf "\nLAMP installed at: http://localhost\n"

printf "\nPHPMYADMIN at: http://localhost/phpmyadmin\n"

printf "\n=> /usr/share/phpmyadmin/$pmaConfig"
printf "\nPMA user: $(sudo cat /usr/share/phpmyadmin/$pmaConfig | grep -n 'controluser')"
printf "\nPMA password: $(sudo cat /usr/share/phpmyadmin/$pmaConfig | grep -n 'controlpass')\n"

printf "\nDONE SUCCESSFULLY...\n"