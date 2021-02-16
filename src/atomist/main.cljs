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
            [cljs-node-io.core :as io]
            [cljs-node-io.proc :as proc]
            [atomist.json :as json]))

(comment
  (->> (io/slurp "/Users/slim/atmhq/bot-service/odc-reports/dependency-check-report.json")
       (json/->obj)
       :dependencies
       (mapcat keys)
       (into #{}))
 ;; dependencies collect evidence for the existence of packages and CPEs, which map to vulnerabilityIds
  #{:description :isVirtual :md5 :license :fileName :evidenceCollected :sha1 :relatedDependencies :vulnerabilityIds :filePath :packages :sha256 :suppressedVulnerabilities :suppressedVulnerabilityIds :vulnerabilities}
  (->> (io/slurp "/Users/slim/atmhq/bot-service/odc-reports/dependency-check-report.json")
       (json/->obj)
       :dependencies
       (map #(gstring/format "%-70s%-10s %d" (:fileName %) (:isVirtual %) (-> % :evidenceCollected count)))
       (cljs.pprint/pprint))
;; vulnerabilityIds are CPEs
  (->> (io/slurp "/Users/slim/atmhq/bot-service/odc-reports/dependency-check-report.json")
       (json/->obj)
       :dependencies
       (filter #(and (:vulnerabilityIds %) (not (empty? (:vulnerabilityIds %)))))
       (map #(gstring/format "%-80s\n\t%-80s\n%s\n%s"
                             (:fileName %)
                             (->> (:packages %)
                                  (map :id)
                                  (interpose ",")
                                  (apply str))
                             (->> (:vulnerabilityIds %)
                                  (map :id)
                                  (map (fn [s] (gstring/format "\t- %s" s)))
                                  (interpose "\n")
                                  (apply str))
                             (->> (:vulnerabilities %))))

       (map println)))

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

(defn report->vulns [org repo commit json]
  (->
   json
   :dependencies
   (as-> deps (->> deps
                   (filter #(or (seq (:vulnerabilityIds %)) (seq (:packages %))))
                   (mapcat (fn [{:keys [fileName license sha256 packages vulnerabilityIds vulnerabilities]}]
                             (concat
                              (->> (seq vulnerabilityIds)
                                   (map-indexed (fn [index {:keys [id confidence url]}]
                                                  (let [cpe-evidence (gstring/format "cpe-evidence-%s-%d" fileName index)]
                                                    [{:schema/entity-type :vulnerability/cpe
                                                      :schema/entity (gstring/format "vuln-%s-%d" fileName index)
                                                      :vulnerability.cpe/evidence {:add [cpe-evidence]}
                                                      :vulnerability.cpe/url id
                                                      :vulnerability.cpe/search-url url}
                                                     {:schema/entity-type :package/evidence
                                                      :schema/entity cpe-evidence
                                                      :package.evidence/dependency fileName
                                                      :package.evidence/source :package.evidence.source/DEPENDENCY_CHECK
                                                      :package.evidence/confidence confidence}])))
                                   (apply concat))
                              (->> (seq packages)
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
                              (->> (seq vulnerabilities)
                                   (map-indexed (fn [index {:keys [source name severity description vulnerableSoftware cwes]
                                                            {:keys [score]} :cvssv2
                                                            {:keys [baseScore]} :cvssv3}]
                                                  {:schema/entity-type :vulnerability/cve
                                                   :schema/entity (gstring/format "cve-%s-%d" fileName index)
                                                   :vulnerability.cve/source-id name
                                                   :vulnerability.cve/source (keyword "vulnerability.cve.source" (s/upper-case source))
                                                   :vulnerability.cve/description description
                                                   :vulnerability.cve/severity (keyword "vulnerability.cve.severity"
                                                                                        (s/upper-case severity))
                                                   :vulnerability.cve/cvss-score (str score)})))
                              [(merge {:schema/entity-type :package/dependency
                                       :schema/entity fileName
                                       :package.dependency/fileName fileName
                                       :package.dependency/sha256 sha256}
                                      (when license {:package.dependency/license license}))])))))
   (as-> entities (concat (into [] entities)
                          [{:schema/entity-type :git/repo
                            :schema/entity "$repo"
                            :git.provider/url (:git.provider/url org)
                            :git.repo/source-id (:git.repo/source-id repo)}
                           {:schema/entity-type :git/commit
                            :schema/entity "$commit"
                            :git.provider/url (:git.provider/url org)
                            :git.commit/sha (:git.commit/sha commit)
                            :git.commit/repo "$repo"

                            ;; add discovered vulnerabilities and dependencies to the Commit 
                            :git.commit/vulnerabilities {:add (->> entities
                                                                   (filter #(= :vulnerability/cve (:schema/entity-type %)))
                                                                   (map :schema/entity)
                                                                   (into []))}
                            :git.commit/dependencies {:add (->> entities
                                                                (filter #(= :package/dependency (:schema/entity-type %)))
                                                                (map :schema/entity)
                                                                (into []))}}]))))

(comment
  (io/spit "transaction.edn"
           (with-out-str
             (pprint (report->vulns
                      {:git.provider/url "url"}
                      {:git.repo/source-id "source-id"}
                      {:git.commit/sha "sha"}
                      (json/->obj (io/slurp "dependency-check-report.json"))))))
  (pprint
   (-> (io/slurp "dependency-check-report.json")
       (json/->obj)
       :dependencies
       (as-> deps (->> deps
                       (filter :vulnerabilities)
                       (mapcat :vulnerabilities)
                       (map #(select-keys % [:source])))))))

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
               args [(gstring/format "--project %s" (:git.repo/name repo))
                     (gstring/format "--scan %s" (.getPath scan-dir))
                     "--format JSON"
                     "--noupdate"
                     (gstring/format "--connectionString %s"
                                     "\"jdbc:mysql://35.237.63.102:3306/dependencycheck?useSSL=false&allowPublicKeyRetrieval=true\"")
                     (gstring/format "--dbDriverName %s" "com.mysql.cj.jdbc.Driver")
                     (gstring/format "--dbDriverPath %s" (.. js/process -env -JDBC_DRIVER_PATH))
                     (gstring/format "--dbPassword %s" (:db-password request))
                     (gstring/format "--dbUser %s" "root")]
               c (async/chan)
               p (proc/spawn command args {})]
           (.on (.-stderr p) "data" (fn [d] (log/error d)))
           (.on (.-stdout p) "data" (fn [d] (log/info d)))
           (.on p "close" (fn [code]
                            (log/info "dependencycheck stopped with code " code)
                            (go (>! c {:code code}))))
           (<! c)
           (when (not (= 0 (:code (<! c))))
             (throw (ex-info "error running dependencycheck" {:error (. err -code)
                                                              :command command
                                                              :args args}))))
         (api/trace "transact")
         (<? (api/transact request (-> (io/slurp "dependency-check-report.json")
                                       (json/->obj)
                                       (as-> json (report->vulns org repo commit json)))))
         (<? (handler (assoc request :atomist/status {:code 0
                                                      :reason "scan complete"}))))
       (catch :default ex
         (log/errorf ex "Error %s\n%s" (.-message ex) (ex-data ex))
         (assoc request
                :atomist/status {:code 1
                                 :reason (gstring/format "Scan failed:  %s" (.-message ex))}))))))

(defn update-nvd-db [handler]
  (fn [request]
    (go-safe
     (try
       (<? (proc/aexec (->> [(.. js/process -env -DEPENDENCY_CHECK)
                             "--updateonly"
                             (gstring/format "--connectionString %s"
                                             "\"jdbc:mysql://35.237.63.102:3306/dependencycheck?useSSL=false&allowPublicKeyRetrieval=true\"")
                             (gstring/format "--dbDriverName %s" "com.mysql.cj.jdbc.Driver")
                             (gstring/format "--dbDriverPath %s" (.. js/process -env -JDBC_DRIVER_PATH))
                             (gstring/format "--dbPassword %s" (:db-password request))
                             (gstring/format "--dbUser %s" "root")]
                            (interpose " ")
                            (apply str))))

       (<? (handler (assoc request :atomist/status {:code 0
                                                    :reason "update NVD database"})))
       (catch :default ex
         (assoc request
                :atomist/status {:code 1
                                 :reason (gstring/format "Update failed:  %s" (.-message ex))}))))))

(defn ^:export handler
  [& _]
  ((-> (api/finished)
       (api/mw-dispatch {:on-nvd-update.edn (-> (api/finished)
                                                (update-nvd-db))
                         :default (-> (api/finished)
                                      (run-scan)
                                      (api/clone-ref)
                                      #_(api/with-github-check-run :name "owasp-dependency-check")
                                      (create-ref-from-event))})
       (api/add-skill-config)
       (api/log-event)
       (api/status)
       (container/mw-make-container-request)) {}))

