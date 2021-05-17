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

(ns atomist.clojure
  (:require [cljs-node-io.core :as io]
            [atomist.async :refer [go-safe <?]]
            [cljs.core.async :refer [<!] :refer-macros [go]]
            [cljs-node-io.proc :as proc]
            [cljs.reader :refer [read-string]]
            [clojure.string :as s]
            [atomist.cljs-log :as log]
            [goog.string :as gstring]
            [goog.string.format]
            [atomist.project :refer [expand-java-project]]
            [clojure.edn :as edn]))

(set! *warn-on-infer* false)

(defn add-mvn-repos-to-deps-edn
  "update :mvn/repos in deps.edn and $HOME/.m2/settings.xml"
  [handler]
  (fn [request]
    (go-safe
     (let [repo-map
           (reduce
            (fn [acc [_ repo usage]]
              (if (and repo usage)
                (update acc (keyword usage) (fn [repos]
                                              (conj (or repos []) repo)))
                acc))
            {}
            (-> request :subscription :result))
           settings-xml
           (gstring/format
            "<settings><servers>%s</servers></settings>"
            (->> (:resolve repo-map)
                 (map (fn [{:maven.repository/keys [repository-id username secret]}]
                        (gstring/format
                         "<server><id>%s</id><username>%s</username><password>%s</password></server>"
                         repository-id
                         username
                         secret)))
                 (apply str)))]
       (when (seq (:resolve repo-map))
         (.mkdirs (io/file ".m2" (.. js/process -env -HOME)))
         (io/spit
          (io/file (gstring/format "%s/.m2/settings.xml" (.. js/process -env -HOME)))
          settings-xml))
       (<? (handler
            (merge
             request
             (when (seq (:resolve repo-map))
               {:mvn/repos
                (->> (:resolve repo-map)
                     (map (fn [{:maven.repository/keys [repository-id url]}]
                            [repository-id {:url url}]))
                     (into {}))}))))))))

(defn get-jars
  "copy all jars to the scan dir"
  [project-dir target-dir]
  (go-safe
   (when (.exists project-dir)
     (let [[err stdout stderr] (<? (proc/aexec "clj -Spath" {:cwd (.getPath project-dir)}))]
       (when err
         (log/error stderr)
         (throw (ex-info "failed to run `clj -Spath`" {:stderr stderr})))
       (doseq [path (s/split stdout #":")]
         (<? (proc/aexec (gstring/format "cp %s %s" path (.getPath target-dir))))))))) 

;; TODO this only supports when files are named deps.edn
(defmethod expand-java-project :deps.edn
  [{edn :mvn/repos} f]
  (go-safe
   (let [scan-dir (io/file (.getParentFile f) "to-scan")]
     (when edn
       (log/info "merging repos into deps.edn " edn)
       (io/spit f (-> (io/slurp f)
                      (read-string)
                      (merge edn))))
     (.mkdirs scan-dir)
     (<? (get-jars (.getParentFile f) scan-dir))
     {:project-file f
      :path scan-dir})))
