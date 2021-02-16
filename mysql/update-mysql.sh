
#export JAVA_OPTS="-Djavax.net.ssl.trustStore=/Users/slim/skills/owasp-dependency-check-skill/mysql/truststore -Djavax.net.ssl.trustStorePassword=dcuser -Djavax.net.ssl.keyStore=/Users/slim/skills/owasp-dependency-check-skill/mysql/keystore -Djavax.net.ssl.keyStorePassword=dcuser"

dependency-check --updateonly \
                 --connectionString="jdbc:mysql://35.237.63.102:3306/dependencycheck?useSSL=false&allowPublicKeyRetrieval=true" \
                 --dbDriverName="com.mysql.cj.jdbc.Driver" \
                 --dbDriverPath="$HOME/.m2/repository/mysql/mysql-connector-java/8.0.21/mysql-connector-java-8.0.21.jar" \
                 --dbUser="root" \
                 --dbPassword="$NVD_MYSQL_PASSWORD"

