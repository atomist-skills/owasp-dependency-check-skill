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

(ns atomist.vulns-test
  (:require [cljs.pprint :refer [pprint]]
            [atomist.main :refer [transact-vulns is-cve?]]
            [atomist.cljs-log :as log]
            [cljs-node-io.core :as io]
            [atomist.json :as json]
            [clojure.edn :as edn]
            [cljs.core.async :refer [<!] :refer-macros [go]]
            [cljs.test :refer-macros [deftest is async]]
            ))

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

(enable-console-print!)

(deftest vuln-tests
  (async
   done
   (go
     (<! ((transact-vulns #(go (is (= 0 (-> % :atomist/status :code))) %))
          {:correlation_id "corrid"
           :sendreponse print-all
           :atomist/file {:entity-type :git.commit/file
                          :entity "$project-file"
                          :git.file/sha "sha"
                          :git.file/path "project.clj"}
           :atomist/file-ref "$project-file"
           :atomist/org {:git.provider/url "url"}
           :atomist/repo {:git.repo/source-id "source-id"}
           :atomist/commit {:git.commit/sha "sha"}
           :atomist/dependency-report (json/->obj (io/slurp "dependency-check-report.json"))}))
     (done))))

(comment
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
