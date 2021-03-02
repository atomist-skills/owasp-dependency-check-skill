# `atomist/owasp-dependency-check`

## TODO

- [ ] only supporting deps.edn/project.clj in root of project

## Model

Analyzers collect "evidence" that a Commit references certain package urls, or CPEs.  Indexes like the OSSINDEX, or
NIST, are used to determine whether the project is impacted by CVEs.


Here's a [picture][model] of the data that we transact during analysis of a Commit.

## Docker

-   added `JDBC_DRIVER_PATH` and `DEPENDENCY_CHECK` (location of
    dependency-check.sh script in image) environment variables to be used by the
    skill runtime.

```
# Docker Build
docker build -t owasp-dependency-check-skill:latest -f docker/Dockerfile .
# Shell-In to Container
docker run -it --entrypoint /bin/sh --user root owasp-dependency-check-skill:latest
```

## Google Mysql Instance for fast CVE lookups

Can connect with mysql client using cli:

```
cd mysql
mysql --user=root --password --host=35.237.63.102
```

After the initial load to a local mysql (not the above one), using
dependencycheck:

```
./mysql/update-mysql.sh
```

I then took a sqldump of the local database and fixed it using sed (weird bug):

```
mysqldump --databases dependencycheck -h localhost -u root -p --hex-blob --single-transaction --set-gtid-purged=OFF --default-character-set=utf8mb4 > dump.sql
sed -i '' 's/utf8mb4_0900_ai_ci/utf8mb4_general_ci/g' 2019-10-26-prod.sql
```

I then uploaded it to a bucket in my project and imported it to my Google Cloud
SQL instance using the console.

## TODO: Prepare the SSL client connection

Switch to using SSL only connections to the DB:

```
mysql --user=root --password --host=35.237.63.102 --ssl-ca=server-ca.pem --ssl-cert=client-cert.pem --ssl-key=client-key.pem
```

Dependency Check will need to run with a JVM that has new keystores and an
additional CA in its default truststore.

-   should we import server-ca.pem into the default cacerts truststore in the
    image jdk?
-   import the client-key and client-cert into a keystore and make sure that the
    JAVA_OPTS sees this keystore

```
keytool -importcert -alias MySQLCACert -file server-ca.pem -keystore truststore -storepass xxxx

openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem -name "mysqlclient" -passout pass:xxxx -out client-keystore.p12
keytool -importkeystore -srckeystore client-keystore.p12 -srcstoretype pkcs12 -srcstorepass dcuser -destkeystore keystore -deststoretype JKS -dest-storepass dcuser
```

## Analyzers

-   `OssIndexAnalyzer` - add Vulnerabilities based on purls - source of CVEs is
    OSSINDEX
-   `CPEAnalyzer` - use evidence to search lucene index
-   `NvdCveAnalyzer` - add vulnerabilities for identified CPEs
-   `CentralAnalyzer` - locate a dependency from central and add the dep's sha
    info
-   `JarAnalyzer` - analyze pom files (adds purl software identifier to
    dependency, as well as other pom based evidence)

OSSINDEX vulnerabilities should be attached to the purl if there's just one.

## Links

-   [initialize mysql instance with this init.sql][init.sql]
-   [base docker image][base-docker-image]

[base-docker-image]: https://hub.docker.com/r/owasp/dependency-check
[init.sql]:
    https://github.com/jeremylong/DependencyCheck/blob/main/core/src/main/resources/data/initialize_mysql.sql
[nvd feed]:
    https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
[cpe 2.3 spec]: https://cpe.mitre.org/specification/
[matching spec]: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
[model]: https://lucid.app/lucidchart/52ba9b78-c54b-40dc-b559-e01b97bbcb31/edit?page=VbVazIvHVe8c#

---

Created by [Atomist][atomist]. Need Help? [Join our Slack workspace][slack].

[atomist]: https://atomist.com/ "Atomist - How Teams Deliver Software"
[slack]: https://join.atomist.com/ "Atomist Community Slack"
