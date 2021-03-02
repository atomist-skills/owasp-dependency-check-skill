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
            [clojure.string :as s]
            [atomist.cljs-log :as log]
            [goog.string :as gstring]
            [goog.string.format]
            [clojure.edn :as edn]))

(defn add-mvn-repos-to-deps-edn
  "update :mvn/repos in deps.edn and $HOME/.m2/settings.xml"
  [handler]
  (fn [request]
    (go-safe
     (let [f (io/file (-> request :project :path) "deps.edn")]
       (when (.exists f)
         (let [repo-map (reduce
                         (fn [acc [_ repo usage]]
                           (if (and repo usage)
                             (update acc (keyword usage) (fn [repos]
                                                           (conj (or repos []) repo)))
                             acc))
                         {}
                         (-> request :subscription :result))]
           (io/spit f (-> (io/slurp f)
                          (edn/read-string)
                          (assoc :mvn/repos (->> (:resolve repo-map)
                                                 (map (fn [{:maven.repository/keys [repository-id url]}]
                                                        [repository-id {:url url}]))
                                                 (into {})))
                          (pr-str)))
           (io/spit
            (io/file (gstring/format "%s/.m2/settings.xml" (.. js/process -env -HOME)))
            (gstring/format
             "<settings><servers>%s</servers></settings>"
             (->> (:resolve repo-map)
                  (map (fn [{:maven.repository/keys [repository-id username secret]}]
                         (gstring/format
                          "<server><id>%s</id><username>%s</username><password>%s</password></server>"
                          repository-id
                          username
                          secret)))
                  (apply str)))))))
     (<? (handler request)))))

(defn get-jars
  "copy all jars to the scan dir"
  [project-dir target-dir]
  (go-safe
   (when (.exists project-dir)
     (.mkdirs target-dir)
     (let [[err stdout stderr] (<? (proc/aexec "clj -Spath" {:cwd (.getPath project-dir)}))]
       (when err
         (log/error stderr)
         (throw (ex-info "failed to run `clj -Spath`" {:stderr stderr})))
       (doseq [path (s/split stdout #":")]
         (<? (proc/aexec (gstring/format "cp %s %s" path (.getPath target-dir))))))))) E
