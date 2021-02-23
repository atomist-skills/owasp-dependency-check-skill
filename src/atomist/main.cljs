;; Copyright © 2021 Atomist, Inc.
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns atomist.main
  (:require [atomist.api :as api]
            [atomist.lein :as lein]
            [cljs.pprint :refer [pprint]]
            [cljs.core.async :refer [<! >!] :refer-macros [go] :as async]
            [atomist.async :refer-macros [go-safe <?]]
            [goog.string.format]
            [goog.string :as gstring]
            [clojure.string :as s]
            [clojure.data]
            [atomist.cljs-log :as log]
            [atomist.github]
            [atomist.container :as container]
            [atomist.local-runner :as lr]
            [cljs-node-io.core :as io]
            [cljs-node-io.proc :as proc]
            [atomist.json :as json]
            [clojure.edn :as edn]))

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

(defn create-ref-from-event
  [handler]
  (fn [request]
    (go-safe
     (let [{:git.commit/keys [repo sha]} (-> request :subscription :result first first)]
       (<? (handler (assoc request :ref {:repo (:git.repo/name repo)
                                         :owner (-> repo :git.repo/org :git.org/name)
                                         :sha sha}
                           :token (-> repo :git.repo/org :github.org/installation-token))))))))

(defn prn-matching-software [{{:keys [id versionStartIncluding versionEndIncluding versionStartExcluding versionEndExcluding]} :software}]
  (gstring/format "%s-%s%s,%s%s"
                  id
                  (cond versionStartExcluding "(" versionStartIncluding "[" :else "(")
                  (or versionStartIncluding versionStartExcluding "")
                  (cond versionEndExcluding "(" versionEndIncluding "[" :else "(")
                  (or versionEndIncluding versionEndExcluding "")))

(defn cpe-match? [cpe1 cpe2 & {:keys [startInc startExc endInc EndExc]}]
  true)

(defn cve-vulnerable?
  "check whether cpe matches the cve using it's matching software data"
  [{:as cpe :vulnerability.cpe/keys [url]}
   {:atomist/keys [matching-software]}]
  (log/infof "compare cpe %s to matching softwares %s"
             (:vulnerability.cpe/url cpe)
             (->> matching-software (map prn-matching-software) (interpose ",") (apply str)))
  (->> matching-software
       (some #(let [{{:keys [id versionStartIncluding versionStartExcluding versionEndIncluding versionEndExcluding]} :software} %]
                (cpe-match? url id
                            :startInc versionStartIncluding
                            :startExc versionStartExcluding
                            :endInc versionEndIncluding
                            :endExc versionEndExcluding)))))

(def is-cve? #(= :vulnerability/cve (:schema/entity-type %)))
(def is-cpe? #(= :vulnerability/cpe (:schema/entity-type %)))
(def is-package-url? #(= :package/url (:schema/entity-type %)))
(def known-source? #(#{:vulnerability.cve.source/NVD :vulnerability.cve.source/RETIREJS :vulnerability.cve.source/OSSINDEX}
                     (:vulnerability.cve/source %)))

(defn link-cpes
  "when a cve has a cpe match, link it to the correct cpe by adding a reference to the :vulnerability.cpe/cves attribute"
  [cpes cves]
  (->> cpes
       (map (fn [{:as cpe}]
              (if (and (is-cpe? cpe))
                (assoc cpe :vulnerability.cpe/cves
                       {:add (->> cves
                                  (filter is-cve?)
                                  (filter (partial cve-vulnerable? cpe))
                                  (map :schema/entity)
                                  (into []))})

                cpe)))
       (into [])))

(defn link-purls
  "when a dependency has only one purl, link it to all discovered CVEs
     or leave the purls unlinked if the number of packages on this dependency is > 1
     only link purls if the cve source is NVD, RETIREJS, or OSSINDEX"
  [purls cves]
  (let [purl-count (->> purls (filter is-package-url?) (count))]
    (if (= 1 purl-count)
      (->> purls
           (map #(if (is-package-url? %)
                   (let [refs (->> cves
                                   (filter is-cve?)
                                   (filter known-source?)
                                   (map :schema/entity)
                                   (into []))]
                     (assoc % :package.url/cves
                            {:add refs}))
                   %))
           (into []))
      (do
        (when (and (> purl-count 1) (seq cves))
          ;; TODO log warning
          (log/warnf "dependency has more than one purl - ambiguous assignment of cpe->cves"))
        purls))))

;; case 1 - no packages (do nothing)
;; case 2 - package(s) only, no CVES (transact package)
;; case 3 - 1 package, 1 CPE, 1 CVE (transact)
;; case 4 - 1 package, 1 CPE, n CVEs (transact)
;; case 5 - 1 package, n CVEs
;; case 6 - 1 package, 1 CPE, no CVEs (transact)
;; case 7 - 1 package, n CPEs (different confidence, no CVEs (transact)
;; case 8 - 1 package, n CPEs, n CVES (***) jetty-server
;; case 9 - 1 package, 1 CPE, 1 CVE but SHADED - (*** humio-sender shades two libraries)
(defn transact-dependency [request org repo commit {:keys [fileName license sha256 packages vulnerabilityIds vulnerabilities]}]
  (go-safe
   (let [cpes (->> (seq vulnerabilityIds)
                   (map-indexed (fn [index {:keys [id confidence url]}]
                                  (let [cpe-evidence (gstring/format "cpe-evidence-%s-%d" fileName index)]
                                    [(merge
                                      {:schema/entity-type :vulnerability/cpe
                                       :schema/entity (gstring/format "vuln-%s-%d" fileName index)
                                       :vulnerability.cpe/evidence {:add [cpe-evidence]}
                                       :vulnerability.cpe/url id}
                                      (when url {:vulnerability.cpe/search-url url}))
                                     {:schema/entity-type :package/evidence
                                      :schema/entity cpe-evidence
                                      :package.evidence/dependency fileName
                                      :package.evidence/source :package.evidence.source/DEPENDENCY_CHECK
                                      :package.evidence/confidence confidence}])))
                   (apply concat))
         purls (->> (seq packages)
                    (map-indexed (fn [index {:keys [id confidence url]}]
                                   (let [package-evidence (gstring/format "package-evidence-%s-%d" fileName index)]
                                     [{:schema/entity-type :package/url
                                       :schema/entity (gstring/format "package-%s-%d" fileName index)
                                       :package.url/evidence {:add [package-evidence]}
                                       :package.url/url id
                                       :package.url/search-url url}
                                      {:schema/entity-type :package/evidence
                                       :schema/entity package-evidence
                                       :package.evidence/dependency fileName
                                       :package.evidence/confidence confidence
                                       :package.evidence/source :package.evidence.source/DEPENDENCY_CHECK}])))
                    (apply concat))
         cves (->> (seq vulnerabilities)
                   (map-indexed (fn [index {:keys [source name severity description vulnerableSoftware cwes]
                                            {:keys [score]} :cvssv2
                                            {:keys [baseScore]} :cvssv3}]
                                  (let [matching-software (->> vulnerableSoftware (filter #(= "true" (-> % :software :vulnerabilityIdMatched))))
                                        cve-ref (gstring/format "cve-%s-%d" fileName index)]
                                    (merge
                                     {:schema/entity-type :vulnerability/cve
                                      :schema/entity cve-ref
                                      :vulnerability.cve/source-id name
                                      :vulnerability.cve/source (keyword "vulnerability.cve.source" (s/upper-case source))
                                      :vulnerability.cve/description description
                                      :vulnerability.cve/severity (keyword "vulnerability.cve.severity"
                                                                           (s/upper-case severity))
                                      :vulnerability.cve/cvss-score (str score)}
                                     (when (seq matching-software)
                                       {:atomist/matching-software matching-software}))))))
         ;; list of cpes, purls, cves, and one dependency
         entities (concat
                   (link-cpes cpes cves)
                   (link-purls purls cves)
                   (->> cves (map #(dissoc % :atomist/matching-software)) (into []))
                   [(merge {:schema/entity-type :package/dependency
                            :schema/entity fileName
                            :package.dependency/fileName fileName
                            :package.dependency/sha256 sha256}
                           (when license {:package.dependency/license license}))])]
     ;; link to Commit and transact
     (<? (api/transact
          request
          (->> entities
               (concat
                [{:schema/entity-type :git/repo
                  :schema/entity "$repo"
                  :git.provider/url (:git.provider/url org)
                  :git.repo/source-id (:git.repo/source-id repo)}
                 {:schema/entity-type :git/commit
                  :schema/entity "$commit"
                  :git.provider/url (:git.provider/url org)
                  :git.commit/sha (:git.commit/sha commit)
                  :git.commit/repo "$repo"

                  ;; add discovered dependencies to the Commit 
                  :git.commit/dependencies {:add (->> entities
                                                      (filter #(= :package/dependency (:schema/entity-type %)))
                                                      (map :schema/entity)
                                                      (into []))}}])
               (into [])))))))

(defn transact-vulns [handler]
  (fn [{:as request :atomist/keys [org repo commit dependency-report]}]
    (go-safe
     (api/trace "transact-vulns")
     (<?  (->>
           dependency-report
           :dependencies
           (filter #(or (seq (:vulnerabilityIds %)) (seq (:packages %))))
           (map (partial transact-dependency request org repo commit))
           (async/merge)
           (async/reduce conj [])))
     (<? (api/transact request [{:schema/entity-type :git/repo
                                 :schema/entity "$repo"
                                 :git.provider/url (:git.provider/url org)
                                 :git.repo/source-id (:git.repo/source-id repo)}
                                {:schema/entity-type :git/commit
                                 :schema/entity "$commit"
                                 :git.provider/url (:git.provider/url org)
                                 :git.commit/sha (:git.commit/sha commit)
                                 :git.commit/repo "$repo"}
                                {:schema/entity-type :dependency.analysis/discovery
                                 :dependency.analysis.discovery/commit "$commit"
                                 :dependency.analysis.discovery/source :dependency.analysis.discovery.source/OWASP_DEPENDENCY_SCANNER
                                 :dependency.analysis.discovery/status :dependency.analysis.discovery.status/COMPLETE}]))
     (<? (handler (assoc request
                         :atomist/status
                         {:code 0
                          :reason "owasp dependency scan complete and discoverable"}))))))

(defn do-nothing [& args] (go true))
(defn js-obj->entities [& args]
  (go (-> args
          first
          (js->clj :keywordize-keys true)
          :entities
          (edn/read-string))))
(defn print-all [& args] (go
                           (let [entities (<! (apply js-obj->entities args))]
                             (when (some is-cve? entities)
                               (cljs.pprint/pprint entities)))
                           true))

(comment
  (go
    (<! ((transact-vulns #(go (log/infof "end with %s" (:atomist/status %)) %))
         {:correlation_id "corrid"
          :sendreponse print-all
          :atomist/org {:git.provider/url "url"}
          :atomist/repo {:git.repo/source-id "source-id"}
          :atomist/commit {:git.commit/sha "sha"}
          :atomist/dependency-report (json/->obj (io/slurp "dependency-check-report.json"))})))
  (enable-console-print!)
  (pprint
   (-> (io/slurp "dependency-check-report.json")
       (json/->obj)
       :dependencies
       (as-> deps (->> deps
                       (map (fn [dep]
                              (select-keys dep [:vulnerabilities :vulnerabilityIds :packages :fileName])))
                       (map (fn [dep]
                              (-> dep
                                  (merge
                                   (when (seq (:vulnerabilities dep))
                                     {:cve-count (count (:vulnerabilities dep))}))
                                  (dissoc :vulnerabilities)))) (map #(->> %)))))))

(defn spawn [command args]
  (go-safe
   (log/info "args " args)
   (let [c (async/chan)
         p (proc/spawn command args {})]
     (.on (.-stderr p) "data" (fn [d] (log/error d)))
     (.on (.-stdout p) "data" (fn [d] (log/info d)))
     (.on p "close" (fn [code]
                      (log/infof "%s stopped with code %s" command code)
                      (go
                        (if (= 0 code)
                          (>! c code)
                          (>! c (ex-info
                                 (gstring/format "%s failed (%s)" command code)
                                 {:code code
                                  :command command
                                  :args args}))))))
     (<! c))))

(defn run-scan [handler]
  (fn [request]
    (go-safe
     (api/trace "run-scan")
     (try
       (let [repo-map (reduce
                       (fn [acc [_ repo usage]]
                         (if (and repo usage)
                           (update acc (keyword usage) (fn [repos]
                                                         (conj (or repos []) repo)))
                           acc))
                       {}
                       (-> request :subscription :result))
             scan-dir (io/file "scan-dir")
             commit (-> request :subscription :result first first)
             repo (:git.commit/repo commit)
             org (:git.repo/org repo)]
         (.mkdirs scan-dir)
         (<? (lein/get-jars (io/file (-> request :project :path)) scan-dir (:resolve repo-map)))
         (let [command (.. js/process -env -DEPENDENCY_CHECK)
               args ["--project" (:git.repo/name repo)
                     "--scan" (.getPath scan-dir)
                     "--format" "JSON"
                     "--noupdate"
                     "--connectionString" "\"jdbc:mysql://35.237.63.102:3306/dependencycheck?useSSL=false&allowPublicKeyRetrieval=true\""
                     "--dbDriverName" "com.mysql.cj.jdbc.Driver"
                     "--dbDriverPath" (.. js/process -env -JDBC_DRIVER_PATH)
                     "--dbPassword" (:db-password request)
                     "--dbUser" "root"]]
           (<? (spawn command args)))
         (<? (handler (assoc request
                             :atomist/dependency-report (-> (io/slurp "dependency-check-report.json")
                                                            (json/->obj))
                             :atomist/org org
                             :atomist/repo repo
                             :atomist/commit commit))))
       (catch :default ex
         (log/errorf ex "Error %s\n%s" (.-message ex) (ex-data ex))
         (assoc request
                :atomist/status {:code 1
                                 :reason (gstring/format "Scan failed:  %s" (.-message ex))}))))))

(defn update-nvd-db [handler]
  (fn [request]
    (go-safe
     (try
       (let [command (.. js/process -env -DEPENDENCY_CHECK)
             args ["--updateonly"
                   "--connectionString" "\"jdbc:mysql://35.237.63.102:3306/dependencycheck?useSSL=false&allowPublicKeyRetrieval=true\""
                   "--dbDriverName" "com.mysql.cj.jdbc.Driver"
                   "--dbDriverPath" (.. js/process -env -JDBC_DRIVER_PATH)
                   "--dbPassword" (:db-password request)
                   "--dbUser" "root"]]
         (<? (spawn command args)))

       (<? (handler (assoc request :atomist/status {:code 0
                                                    :reason "update NVD database"})))
       (catch :default ex
         (assoc request
                :atomist/status {:code 1
                                 :reason (gstring/format "Update failed:  %s" (.-message ex))}))))))

(defn neutral-milk-party [handler]
  (fn [request]
    (go-safe
     (let [{:git.commit/keys [sha]} (-> request :subscription :result first first)
           summary (->> (-> request :subscription :result first)
                        (map second)
                        (map (fn [{:vulnerability.cve/keys [source-id source cvss-score]
                                   cpes :vulnerability.cpe/_cves
                                   packages :package.url/_cves}]
                               (gstring/format "%-20s%-10s(%-5s) -- %s - %s" source-id source cvss-score cpes packages)))
                        (interpose "\n* ")
                        (apply str))]
       (<? (handler (assoc request
                           :atomist/status {:code 0 :reason "discovered scan"}
                           :checkrun/output {:title "OWasp Scan Results"
                                             :summary summary}
                           :checkrun/conclusion "neutral")))))))

(defn ^:export handler
  [& _]
  ((-> (api/finished)
       (api/mw-dispatch {:on-nvd-update.edn (-> (api/finished)
                                                (update-nvd-db))
                         :on-discovery.edn (-> (api/finished)
                                               (neutral-milk-party)
                                               (api/with-github-check-run :name "owasp-dependency-check")
                                               (create-ref-from-event))
                         :default (-> (api/finished)
                                      (transact-vulns)
                                      (run-scan)
                                      (api/clone-ref)
                                      #_(api/with-github-check-run :name "owasp-dependency-check")
                                      (create-ref-from-event))})
       (api/add-skill-config)
       (api/log-event)
       (api/status)
       (container/mw-make-container-request)) {}))

