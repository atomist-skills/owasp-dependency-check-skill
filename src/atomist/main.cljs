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
            [atomist.clojure :as clojure]
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
   (let [commit-ref "$commit"
         cpes (->> (seq vulnerabilityIds)
                   (map-indexed (fn [index {:keys [id confidence url]}]
                                  (let [cpe-evidence (gstring/format "cpe-evidence-%s-%d" fileName index)
                                        cpe (gstring/format "cpe-%s-%d" fileName index)]
                                    [(merge
                                      {:schema/entity-type :vulnerability/cpe
                                       :schema/entity cpe
                                       :vulnerability.cpe/url id}
                                      (when url {:vulnerability.cpe/search-url url}))
                                     {:schema/entity-type :package/evidence
                                      :schema/entity cpe-evidence
                                      :package.evidence/commit commit-ref
                                      :package.evidence/dependency fileName
                                      :package.evidence/cpe cpe
                                      :package.evidence/source :package.evidence.source/DEPENDENCY_CHECK
                                      :package.evidence/confidence confidence}])))
                   (apply concat))
         purls (->> (seq packages)
                    (map-indexed (fn [index {:keys [id confidence url]}]
                                   (let [package-evidence (gstring/format "package-evidence-%s-%d" fileName index)
                                         purl (gstring/format "package-%s-%d" fileName index)]
                                     [{:schema/entity-type :package/url
                                       :schema/entity purl
                                       :package.url/url id
                                       :package.url/search-url url}
                                      {:schema/entity-type :package/evidence
                                       :schema/entity package-evidence
                                       :package.evidence/commit commit-ref
                                       :package.evidence/dependency fileName
                                       :package.evidence/purl purl
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
                  :schema/entity commit-ref
                  :git.provider/url (:git.provider/url org)
                  :git.commit/sha (:git.commit/sha commit)
                  :git.commit/repo "$repo"}])
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
       (let [project-dir (io/file (-> request :project :path))
             scan-dir (io/file "scan-dir")
             commit (-> request :subscription :result first first)
             repo (:git.commit/repo commit)
             org (:git.repo/org repo)
             deps-edn (io/file project-dir "deps.edn")
             project-clj (io/file project-dir "project.clj")]
         (.mkdirs scan-dir)
         (when (.exists project-clj)
           (<? (lein/get-jars project-dir scan-dir)))
         (when (.exists deps-edn)
           (<? (clojure/get-jars project-dir scan-dir)))
         (let [command (.. js/process -env -DEPENDENCY_CHECK)
               args ["--project" (:git.repo/name repo)
                     "--scan" (.getPath scan-dir)
                     "--format" "JSON"
                     "--noupdate"
                     "--connectionString" "\"jdbc:mysql://35.237.63.102:3306/dependencycheck?useSSL=false&allowPublicKeyRetrieval=true\""
                     "--dbDriverName" "com.mysql.cj.jdbc.Driver"
                     "--dbDriverPath" (.. js/process -env -JDBC_DRIVER_PATH)
                     "--dbPassword" (:nvd-mysql-password request)
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
                   "--dbPassword" (:nvd-mysql-password request)
                   "--dbUser" "root"]]
         (<? (spawn command args)))

       (<? (handler (assoc request :atomist/status {:code 0
                                                    :reason "update NVD database"})))
       (catch :default ex
         (assoc request
                :atomist/status {:code 1
                                 :reason (gstring/format "Update failed:  %s" (.-message ex))}))))))

(defn report [x]
  (->> x
       (map second)
       (map (fn [{:package.evidence/keys [confidence source purl cpe]
                  {:package.dependency/keys [license fileName]} :package.evidence/dependency}]
              (-> {}
                  (merge
                   (if purl
                     {:purl (:package.url/url purl)}))
                  (merge
                   (if cpe
                     {:cpe (:vulnerability.cpe/url cpe)}))
                  (merge
                   {:license license
                    :fileName fileName
                    :confidence confidence
                    :source (-> source :db/ident name)
                    :cves (->> (or (:vulnerability.cpe/cves cpe) (:package.url/cves purl))
                               (map (fn [{:vulnerability.cve/keys [severity cvss-score source-id]}]
                                      {:cvss-score cvss-score
                                       :id source-id
                                       :severity (-> severity :db/ident keyword name)}))
                               (into []))}))))
       (reduce (fn [s {:keys [license fileName confidence source cves cpe purl]}]
                 (str s "\n" (gstring/format
                              "|%s|%s|%s|%s|%s|"
                              (str
                               (if purl
                                 (gstring/format "`%s`" purl)
                                 "")
                               "<br/>"
                               (if cpe
                                 (gstring/format "`%s`" cpe)
                                 ""))
                              fileName
                              confidence
                              (->> cves
                                   (map (fn [{:keys [severity cvss-score id]}]
                                          (gstring/format "(%s, %s, cvss=%s)" id (or severity "") (or cvss-score ""))))
                                   (interpose ", ")
                                   (apply str))
                              (or license "unknown"))))
               (str
                "|package|fileName|confidence|CVEs |license|"
                "\n"
                "| :---  | :---   | :----    | :-- | :---  |"))))

(defn check-run-report [handler]
  (fn [request]
    (go-safe
     (let [{:git.commit/keys [sha]} (-> request :subscription :result first first)
           summary (report (-> request :subscription :result))]
       (<? (handler (assoc request
                           :atomist/status {:code 0 :reason "discovered scan"}
                           :checkrun/output {:title "OWasp Scan Results"
                                             :summary "summary"
                                             :text summary}
                           :checkrun/conclusion "neutral")))))))

(defn ^:export handler
  [& _]
  ((-> (api/finished)
       (api/mw-dispatch {:on-nvd-update.edn (-> (api/finished)
                                                (update-nvd-db))
                         :on-discovery.edn (-> (api/finished)
                                               (check-run-report)
                                               (api/with-github-check-run :name "owasp-dependency-check-skill/scanned")
                                               (create-ref-from-event))
                         :default (-> (api/finished)
                                      (transact-vulns)
                                      (run-scan)
                                      (lein/add-lein-profiles)
                                      (clojure/add-mvn-repos-to-deps-edn)
                                      (api/clone-ref)
                                      #_(api/with-github-check-run :name "owasp-dependency-check")
                                      (create-ref-from-event))})
       (api/add-skill-config)
       (api/log-event)
       (api/status)
       (container/mw-make-container-request)) {}))

