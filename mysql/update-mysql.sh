# Copyright © 2021 Atomist, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#export JAVA_OPTS="-Djavax.net.ssl.trustStore=/Users/slim/skills/owasp-dependency-check-skill/mysql/truststore -Djavax.net.ssl.trustStorePassword=dcuser -Djavax.net.ssl.keyStore=/Users/slim/skills/owasp-dependency-check-skill/mysql/keystore -Djavax.net.ssl.keyStorePassword=dcuser"

dependency-check --updateonly \
                 --connectionString="jdbc:mysql://35.237.63.102:3306/dependencycheck?useSSL=false&allowPublicKeyRetrieval=true" \
                 --dbDriverName="com.mysql.cj.jdbc.Driver" \
                 --dbDriverPath="$HOME/.m2/repository/mysql/mysql-connector-java/8.0.21/mysql-connector-java-8.0.21.jar" \
                 --dbUser="root" \
                 --dbPassword="$NVD_MYSQL_PASSWORD"

