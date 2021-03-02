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

(ns atomist.lein
  (:require [cljs-node-io.core :as io]
            [atomist.async :refer [go-safe <?]]
            [cljs.core.async :refer [<!] :refer-macros [go]]
            [cljs-node-io.proc :as proc]
            [clojure.string :as str]
            [atomist.cljs-log :as log]
            [goog.string :as gstring]
            [goog.string.format]))

(defn add-lein-profiles
  "add the lein profiles.clj in all cases (even if there's no lein project.clj)"
  [handler]
  (fn [request]
    (go-safe
     (let [repo-map (reduce
                     (fn [acc [_ repo usage]]
                       (if (and repo usage)
                         (update acc (keyword usage) (fn [repos]
                                                       (conj (or repos []) repo)))
                         acc))
                     {}
                     (-> request :subscription :result))]

       (log/infof "Found resolve integration: %s"
                  (->> (:resolve repo-map)
                       (map #(gstring/format "%s - %s" (:maven.repository/repository-id %) (:maven.repository/url %)))
                       (str/join ", ")))

       (io/spit
        (io/file (-> request :project :path) "profiles.clj")
        (pr-str
         {:resolve-repos
          {:repositories (->> (:resolve repo-map)
                              (map (fn [{:maven.repository/keys [repository-id url username secret]}]
                                     (log/infof "add-resolve profiles.clj profile for %s with user %s and password %s"
                                                url
                                                username
                                                (apply str (take (count secret) (repeat 'X))))
                                     [repository-id {:url url
                                                     :username username
                                                     :password secret}]))
                              (into []))}}))
       (<! (handler request))))))

(defn get-jars
  "copy all jars into the scan dir"
  [project-dir target-dir]
  (go-safe
   (when (.exists project-dir)
     (.mkdirs target-dir)
     (let [[err stdout stderr] (<? (proc/aexec "lein with-profile resolve-repos cp"
                                               {:cwd (.getPath project-dir)}))]
       (when err
         (log/error stderr)
         (throw (ex-info "failed to run `lein cp`" {:stderr stderr})))
       (doseq [path (str/split stdout #":")]
         (<? (proc/aexec (gstring/format "cp %s %s" path (.getPath target-dir)))))))))

(comment
  (go
    (<! ((-> (fn [request]
               (go
                 (<! (get-jars (io/file (-> request :project :path)) (io/file "jar-lib")))
                 request))
             (add-lein-profiles))
         {:project
          {:path "/Users/slim/atmhq/bot-service"}
          :subscription
          {:result [[nil
                     {:maven.repository/repository-id "repo-id"
                      :maven.repository/url "url"
                      :maven.repository/username "username"
                      :maven.repository/secret "password"}
                     "resolve"]]}}))))
