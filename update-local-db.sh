# Copyright © 2020 Atomist, Inc.
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

DC_VERSION="latest"

docker run --rm \
    --volume /Users/slim/.m2/repository:/root/.m2/repository:z \
    -p 3306:3306 \
    owasp/dependency-check:$DC_VERSION \
    --updateonly \
    --connectionString "jdbc:mysql://host.docker.internal:3306/dependencycheck?useSSL=false&allowPublicKeyRetrieval=true" \
    --dbDriverName com.mysql.cj.jdbc.Driver \
    --dbDriverPath /root/.m2/repository/mysql/mysql-connector-java/8.0.21/mysql-connector-java-8.0.21.jar \
    --dbPassword $NVD_MYSQL_PASSWORD \
    --dbUser dcuser
