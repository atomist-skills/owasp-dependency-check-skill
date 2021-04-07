# `atomist/owasp-dependency-check`

;; sonatype OSS Index
;; https://ossindex.sonatype.org/component/pkg:npm/jquery@1.8.0.min
;;  https://blog.sonatype.com/how-to-use-sonatype-oss-index-to-identify-security-vulnerabilities
;;
;; Common Vulnerability Scoring System
;;  https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System
;;
;; fileName, md5, sha1, sha256, description, license, evidenceCollected, packages, vulnerabilities, vulnerabilityIds,
;; suppressedVulnerabilities, suppressedVulnerabilityIds, relatedDependencies
;; https://github.com/jeremylong/DependencyCheck/blob/main/core/src/main/resources/data/initialize_postgres.sql
;;
;; dependency -> evidenceCollected -> packages
;;   packages [id, confidence, url]
;; isVirtual - file does not actual exist

;; CPE Common Platform Enumeration (https://nvd.nist.gov/products/cpe)
;;   produce, vendor, version
;;   cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*
;;   cpe:/[Entry Type]:[Vendor]:[Product]:[Version]:[Revision]:…
;;   cpe:/ part : vendor : product : version : update : edition : language
;; CVE Common Vulnerability and Exposure
;;    CVEs are a mapping between a vulnerability entry and a set of CPEs

;; CVE and CPE together form a Vulnerability Management System (VMS)
;;   https://www.groundai.com/project/software-vulnerability-analysis-using-cpe-and-cve/1
;;   CVE entries without CPE entries
;;   https://storage.googleapis.com/groundai-web-prod/media%2Fusers%2Fuser_214429%2Fproject_336952%2Fimages%2Foverview.jpg
;; 
;; https://nvd.nist.gov/vuln/data-feeds

;; suppressions
;;   by sha1, or filePath (regex), or packageUrl (regex)
;;     suppress cve, or cpe, or vulnerabilityName (regex)
;;   by cvssBelow

;; bom formats
;; https://cyclonedx.org/
;; https://spdx.dev/

;; scanInfo
;; projectInfo
;; dependencies 
'(:description :isVirtual :md5 :license :fileName :evidenceCollected :sha1 :filePath :packages :sha256 :vulnerabilityIds :vulnerabilities)
;;   evidenceCollected is used to make decisions about packages
;;   vulnerabilityIds are really where we display confidence about how we've mapped evidence to CPEs (and subsequently
;;   to CVES
;;   vulnerabilityIds have :id :confidence :url
;;   vulnerabilities are :source :name :severity :cvssv2 :cvssv3 :cwes :description :notes :references :vulnerableSoftware

;; purl -> CPE mapping
;; https://github.com/OSSIndex/vulns/issues/53
;; 

;; https://security-team.debian.org/
;; https://security-tracker.debian.org/tracker/
;; https://security-team.debian.org/security_tracker.html
;; they download the CVE list twice per day and update their repo.  Their team then manually
;; checks whether any debian packages are impacted and maintains the mapping from CVE -> debian
;; package and may even create the CPE entry

;; https://ossindex.sonatype.org/
;; 

;; https://github.com/jeremylong/DependencyCheck/blob/main/Dockerfile
;; https://hub.docker.com/layers/clojure/library/clojure/openjdk-15-lein-alpine/images/sha256-d6a03ef67e1d15bc276c52750da971fd6725162e7d93042b69fb500caeee0aa2?context=explore 
;; https://github.com/package-url/purl-spec

## TODO

-   [ ] only supporting deps.edn/project.clj in root of project

## Model

Analyzers collect "evidence" that a Commit references certain package urls, or
CPEs. Indexes like the OSSINDEX, or NIST, are used to determine whether the
project is impacted by CVEs.

Here's a [picture][model] of the data that we transact during analysis of a
Commit.

## Setting up DB

### 1 Local DB

Start with a local mysql db.

```
$:> mysql.server start
$:> mysql -uroot -hlocalhost -p
mysql> CREATE database dependencycheck;
mysql> CREATE user 'dcuser'@'localhost' identified by 'xxxxxxx'
mysql> grant all privileges on dependencycheck.* to 'dcuser'@'localhost';
mysql> source dependencycheck/core/src/main/resources/data/initialize_mysql.sql
```

and then a local docker container pointed at this local db. This should
initialize the DB fully.

```
update-local-db.sh
```

### 2 dump all the data from the local db

This is really to speed up the initialization of the remote DB.

```
mysqldump --databases dependencycheck -h localhost -u root -p --hex-blob --single-transaction --set-gtid-purged=OFF --default-character-set=utf8mb4 > dump.sql
sed -i '' 's/utf8mb4_0900_ai_ci/utf8mb4_general_ci/g' dump.sql
```

Upload it to a bucket in the google project and then imported it to my Google
Cloud SQL instance using the console.

You'll need to have prepped the remote db first:

```
mysql --user=root --password --host=35.237.63.102 < ./dependencycheck/core/src/main/resources/data/initialize_mysql.sql
mysql --user=root --password --host=35.237.63.102
```

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
[model]:
    https://lucid.app/lucidchart/52ba9b78-c54b-40dc-b559-e01b97bbcb31/edit?page=VbVazIvHVe8c#

---

Created by [Atomist][atomist]. Need Help? [Join our Slack workspace][slack].

[atomist]: https://atomist.com/ "Atomist - How Teams Deliver Software"
[slack]: https://join.atomist.com/ "Atomist Community Slack"
