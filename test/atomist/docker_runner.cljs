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

(ns atomist.docker-runner
  (:require [goog.string :as gstring]
            [cljs-node-io.core :as io]
            [cljs-node-io.proc :as proc]
            [atomist.async :refer-macros [<? go-safe]]
            [cljs.core.async :refer [<! >!] :refer-macros [go] :as async]
            [atomist.cljs-log :as log]
            [atomist.json :as json]
            [atomist.api :as api]))

(defn atomist-payload [{:keys [parameters team-id result correlation-id subscription]}]
  {:skill 
   {:namespace "atomist" 
    :name ""
    :configuration
    {:name ""
     :resourceProviders []
     :capabilities []
     :parameters parameters}}
   :subscription subscription
   :team {:id team-id}
   :correlation_id correlation-id
   :correlation-id correlation-id
   :type "datalog_subscription_result"
   :secrets [{:uri "atomist://api-key" :value (.. js/process -env -API_KEY_PROD)}]})

(defn docker-args [{:keys [image team-id correlation-id]}] 
  ["run" 
   "--rm" 
   "--env" (gstring/format "WORKSPACE_ID=%s" team-id)   
   "--env" (gstring/format "GRAPHQL_ENDPOINT=%s" "https://automation.atomist.com/graphql") 
   "--env" (gstring/format "ATOMIST_PAYLOAD=%s" "/atomist/payload.json") 
   "--env" (gstring/format "ATOMIST_CORRELATION_ID=%s" correlation-id) 
   "--env" (gstring/format "TOPIC=%s" "NONE") 
   "--env" (gstring/format "STORAGE=%s" "gs://none") 
   "--env" "LOCAL_SKILL_RUNNER=true"
   "--volume" (gstring/format "%s:%s" "/tmp" "/atomist")
   image])

(defn run-docker [m]
  (io/spit "/tmp/payload.json" (-> (atomist-payload m) 
                                   (clj->js :keyword-fn #(.-fqn %))
                                   (js/JSON.stringify nil 2)))
  (go-safe 
    (let [c (async/chan)
          p (proc/spawn "docker" (docker-args m) {})] (.on (.-stdout p) "data" (fn [d] (log/info d)))
     (.on (.-stderr p) "data" (fn [d] (log/error d)))
     (.on p "close" (fn [code] 
                      (log/info "docker closed with code " code) 
                      (go (>! c :closed))))
     (<! c))))

(defn get-installation-token [team-id owner]
  (go (<! ((-> (fn [request] (go (:token request)))
               (api/extract-github-token))
           {:ref {:owner owner}
            :team {:id team-id}
            :secrets [{:uri "atomist://api-key" :value (.. js/process -env -API_KEY_PROD)}]}))))

(comment
  (go
    (<!
     (run-docker {:team-id "T095SFFBK"
                  :image "owasp-dependency-check-skill:latest"
                  :correlation-id "corrid"
                  :parameters [{:name "db-password" :value (.. js/process -env -NVD_MYSQL_PASSWORD)}]
                  :subscription {:name "push-with-content.edn"
                                 :result [[{:git.commit/sha "ce4f289517cc153e9ec16cc3e266fcefe5961cb3"
                                            :git.commit/repo
                                            {:git.repo/name "bot-service"
                                             :git.repo/org
                                             {:git.org/name "atomisthq"
                                              :github.org/installation-token (<! (get-installation-token "T095SFFBK" "atomisthq"))}}}
                                           {:maven.repository/url ""
                                            :maven.repository/secret (.. js/process -env -MVN_ARTIFACTORYMAVENREPOSITORY_PWD)
                                            :maven.repository/username (.. js/process -env -MVN_ARTIFACTORYMAVENREPOSITORY_USER)
                                            :maven.repository/repository-id "resolve"}
                                           "resolve"]]}}))))
